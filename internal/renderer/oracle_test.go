//go:build oracle

package renderer

// This file is an optional comparison harness between the Go port and the
// frozen PHP renderer. It is excluded from normal builds via the "oracle" build
// tag so that `go test ./internal/renderer` never depends on external files.
//
// Usage (from the repository root, after generating the fixtures and oracle
// outputs with the docker PHP image):
//
//	RENDERER_EVIDENCE=$PWD/.local/refactoring/evidence/2026-10-30-m3-06-renderer \
//	    go test -tags oracle ./internal/renderer -run TestOracleComparison -v
//
// It writes the Go renders to <evidence>/go, side-by-side comparison PNGs to
// <evidence>/compare, and the numeric report to <evidence>/comparison.{json,md}.

import (
	"encoding/json"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type fixtureEntry struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Slim        bool   `json:"slim"`
	Description string `json:"description"`
}

type fixturesFile struct {
	Fixtures []fixtureEntry `json:"fixtures"`
}

type oracleOutput struct {
	File   string `json:"file"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	SHA256 string `json:"sha256"`
}

type oracleFixture struct {
	Name    string                  `json:"name"`
	Fixture string                  `json:"fixture"`
	Slim    bool                    `json:"slim"`
	IsAlex  bool                    `json:"isAlex"`
	Outputs map[string]oracleOutput `json:"outputs"`
}

type oracleManifest struct {
	Generator string          `json:"generator"`
	Fixtures  []oracleFixture `json:"fixtures"`
}

type imageComparison struct {
	Fixture        string  `json:"fixture"`
	Kind           string  `json:"kind"`
	OracleWidth    int     `json:"oracleWidth"`
	OracleHeight   int     `json:"oracleHeight"`
	GoWidth        int     `json:"goWidth"`
	GoHeight       int     `json:"goHeight"`
	DimensionsSame bool    `json:"dimensionsSame"`
	Pixels         int     `json:"pixels"`
	DiffPixels     int     `json:"diffPixels"`
	DiffRatio      float64 `json:"diffRatio"`
	MaxChannelDiff int     `json:"maxChannelDiff"`
	MeanAbsDiff    float64 `json:"meanAbsDiff"`
	Over2Pixels    int     `json:"over2Pixels"`
	Over8Pixels    int     `json:"over8Pixels"`
	Identical      bool    `json:"identical"`
}

type comparisonReport struct {
	Oracle      string            `json:"oracle"`
	Images      []imageComparison `json:"images"`
	TotalImages int               `json:"totalImages"`
	Identical   int               `json:"identicalImages"`
	DimensionOK int               `json:"dimensionMatches"`
	MaxDiff     int               `json:"maxChannelDiff"`
	MeanRatio   float64           `json:"meanDiffRatio"`
	WorstRatio  float64           `json:"worstDiffRatio"`
	AlexMatches int               `json:"isAlexMatches"`
	AlexChecked int               `json:"isAlexChecked"`
}

func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return png.Decode(f)
}

func savePNG(path string, src image.Image) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, src)
}

func toNRGBA(src image.Image) *image.NRGBA {
	b := src.Bounds()
	out := image.NewNRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(out, out.Bounds(), src, b.Min, draw.Src)
	return out
}

func pixelDiff(a, b *image.NRGBA, x, y int) (maxDiff int, sum int) {
	ia := a.PixOffset(x, y)
	ib := b.PixOffset(x, y)
	for ch := 0; ch < 4; ch++ {
		d := int(a.Pix[ia+ch]) - int(b.Pix[ib+ch])
		if d < 0 {
			d = -d
		}
		if d > maxDiff {
			maxDiff = d
		}
		sum += d
	}
	return maxDiff, sum
}

// composeComparison lays out oracle, Go and amplified-diff panels side by side
// on a white background.
func composeComparison(oracleImg, goImg *image.NRGBA) *image.NRGBA {
	gap := 12
	w := oracleImg.Bounds().Dx() + goImg.Bounds().Dx() + oracleImg.Bounds().Dx() + gap*2
	h := oracleImg.Bounds().Dy()
	if goImg.Bounds().Dy() > h {
		h = goImg.Bounds().Dy()
	}
	out := image.NewNRGBA(image.Rect(0, 0, w, h))
	// White background.
	for i := 0; i < len(out.Pix); i += 4 {
		out.Pix[i], out.Pix[i+1], out.Pix[i+2], out.Pix[i+3] = 255, 255, 255, 255
	}
	drawOver := func(panel *image.NRGBA, dx int) {
		// Alpha-composite over white so transparent areas are visible.
		for y := 0; y < panel.Bounds().Dy(); y++ {
			for x := 0; x < panel.Bounds().Dx(); x++ {
				si := panel.PixOffset(x, y)
				a := uint32(panel.Pix[si+3])
				inv := 255 - a
				di := out.PixOffset(dx+x, y)
				for ch := 0; ch < 3; ch++ {
					out.Pix[di+ch] = uint8((uint32(panel.Pix[si+ch])*a + 255*inv) / 255)
				}
				out.Pix[di+3] = 255
			}
		}
	}
	drawOver(oracleImg, 0)
	drawOver(goImg, oracleImg.Bounds().Dx()+gap)

	diffX := oracleImg.Bounds().Dx() + goImg.Bounds().Dx() + gap*2
	for y := 0; y < oracleImg.Bounds().Dy() && y < goImg.Bounds().Dy(); y++ {
		for x := 0; x < oracleImg.Bounds().Dx() && x < goImg.Bounds().Dx(); x++ {
			d, _ := pixelDiff(oracleImg, goImg, x, y)
			di := out.PixOffset(diffX+x, y)
			if d == 0 {
				out.Pix[di], out.Pix[di+1], out.Pix[di+2] = 235, 235, 235
			} else {
				g := 255 - d*6
				if g < 0 {
					g = 0
				}
				out.Pix[di], out.Pix[di+1], out.Pix[di+2] = 255, uint8(g), uint8(g)
			}
			out.Pix[di+3] = 255
		}
	}
	return out
}

func TestOracleComparison(t *testing.T) {
	evidence := os.Getenv("RENDERER_EVIDENCE")
	if evidence == "" {
		t.Skip("set RENDERER_EVIDENCE to the evidence directory to compare against the PHP oracle")
	}

	var fixtures fixturesFile
	raw, err := os.ReadFile(filepath.Join(evidence, "fixtures", "fixtures.json"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatalf("parse fixtures: %v", err)
	}
	var manifest oracleManifest
	raw, err = os.ReadFile(filepath.Join(evidence, "oracle", "manifest.json"))
	if err != nil {
		t.Fatalf("read oracle manifest: %v", err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse oracle manifest: %v", err)
	}

	oracleByName := make(map[string]oracleFixture, len(manifest.Fixtures))
	for _, of := range manifest.Fixtures {
		oracleByName[of.Name] = of
	}

	goDir := filepath.Join(evidence, "go")
	cmpDir := filepath.Join(evidence, "compare")
	for _, dir := range []string{goDir, cmpDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	report := comparisonReport{Oracle: manifest.Generator}
	var ratios []float64

	for _, fixture := range fixtures.Fixtures {
		of, ok := oracleByName[fixture.Name]
		if !ok {
			t.Fatalf("fixture %q missing from oracle manifest", fixture.Name)
		}

		src, err := loadPNG(filepath.Join(evidence, "fixtures", fixture.File))
		if err != nil {
			t.Fatalf("decode fixture %s: %v", fixture.File, err)
		}

		renders := map[string]image.Image{
			"preview":  Skin(src, 12, fixture.Slim),
			"cape":     Cape(src, 200),
			"avatar2d": Avatar2D(src, 25),
			"avatar3d": Avatar3D(src, 25),
		}
		kinds := []string{"preview", "cape", "avatar2d", "avatar3d"}
		sort.Strings(kinds)

		for _, kind := range kinds {
			goImg := toNRGBA(renders[kind])
			goPath := filepath.Join(goDir, fmt.Sprintf("%s.%s.png", fixture.Name, kind))
			if err := savePNG(goPath, goImg); err != nil {
				t.Fatalf("save %s: %v", goPath, err)
			}

			oracleOutput := of.Outputs[kind]
			oracleImg, err := loadPNG(filepath.Join(evidence, "oracle", oracleOutput.File))
			if err != nil {
				t.Fatalf("decode oracle %s: %v", oracleOutput.File, err)
			}
			oracleNRGBA := toNRGBA(oracleImg)

			cmp := imageComparison{
				Fixture:        fixture.Name,
				Kind:           kind,
				OracleWidth:    oracleNRGBA.Bounds().Dx(),
				OracleHeight:   oracleNRGBA.Bounds().Dy(),
				GoWidth:        goImg.Bounds().Dx(),
				GoHeight:       goImg.Bounds().Dy(),
				DimensionsSame: oracleNRGBA.Bounds().Dx() == goImg.Bounds().Dx() && oracleNRGBA.Bounds().Dy() == goImg.Bounds().Dy(),
			}
			if cmp.DimensionsSame {
				cmp.Pixels = cmp.OracleWidth * cmp.OracleHeight
				totalAbs := 0
				for y := 0; y < cmp.OracleHeight; y++ {
					for x := 0; x < cmp.OracleWidth; x++ {
						maxDiff, sum := pixelDiff(oracleNRGBA, goImg, x, y)
						totalAbs += sum
						if maxDiff != 0 {
							cmp.DiffPixels++
						}
						if maxDiff > 2 {
							cmp.Over2Pixels++
						}
						if maxDiff > 8 {
							cmp.Over8Pixels++
						}
						if maxDiff > cmp.MaxChannelDiff {
							cmp.MaxChannelDiff = maxDiff
						}
					}
				}
				cmp.DiffRatio = float64(cmp.DiffPixels) / float64(cmp.Pixels)
				cmp.MeanAbsDiff = float64(totalAbs) / float64(cmp.Pixels*4)
				cmp.Identical = cmp.DiffPixels == 0
				ratios = append(ratios, cmp.DiffRatio)
			}
			report.Images = append(report.Images, cmp)

			composite := composeComparison(oracleNRGBA, goImg)
			cmpPath := filepath.Join(cmpDir, fmt.Sprintf("%s.%s.compare.png", fixture.Name, kind))
			if err := savePNG(cmpPath, composite); err != nil {
				t.Fatalf("save %s: %v", cmpPath, err)
			}
		}

		// IsAlex check.
		report.AlexChecked++
		if got := IsAlex(src); got == of.IsAlex {
			report.AlexMatches++
		} else {
			t.Errorf("IsAlex(%s) = %v, oracle %v", fixture.Name, got, of.IsAlex)
		}
	}

	report.TotalImages = len(report.Images)
	for _, cmp := range report.Images {
		if cmp.Identical {
			report.Identical++
		}
		if cmp.DimensionsSame {
			report.DimensionOK++
		}
		if cmp.MaxChannelDiff > report.MaxDiff {
			report.MaxDiff = cmp.MaxChannelDiff
		}
		if cmp.DiffRatio > report.WorstRatio {
			report.WorstRatio = cmp.DiffRatio
		}
	}
	if len(ratios) > 0 {
		var sum float64
		for _, r := range ratios {
			sum += r
		}
		report.MeanRatio = sum / float64(len(ratios))
	}

	writeReport(t, evidence, report)
}

func writeReport(t *testing.T, evidence string, report comparisonReport) {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if err := os.WriteFile(filepath.Join(evidence, "comparison.json"), append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write comparison.json: %v", err)
	}

	md := "# Go renderer vs frozen PHP oracle\n\n"
	md += fmt.Sprintf("Oracle: %s\n\n", report.Oracle)
	md += fmt.Sprintf("Images: %d, dimension matches: %d, pixel-identical: %d, max channel diff: %d, mean differing-pixel ratio: %.4f%%, worst: %.4f%%\n\n",
		report.TotalImages, report.DimensionOK, report.Identical, report.MaxDiff, report.MeanRatio*100, report.WorstRatio*100)
	md += "| fixture | kind | size | differing px | ratio | max diff | >2 | >8 | mean abs |\n"
	md += "| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n"
	for _, cmp := range report.Images {
		md += fmt.Sprintf("| %s | %s | %dx%d | %d | %.4f%% | %d | %d | %d | %.3f |\n",
			cmp.Fixture, cmp.Kind, cmp.GoWidth, cmp.GoHeight, cmp.DiffPixels, cmp.DiffRatio*100,
			cmp.MaxChannelDiff, cmp.Over2Pixels, cmp.Over8Pixels, cmp.MeanAbsDiff)
	}
	if err := os.WriteFile(filepath.Join(evidence, "comparison.md"), []byte(md), 0o644); err != nil {
		t.Fatalf("write comparison.md: %v", err)
	}
	t.Logf("wrote %s and comparison.md", filepath.Join(evidence, "comparison.json"))
	assertDiffBounded(t, report)
}

// assertDiffBounded keeps the harness honest: the port must be pixel-identical
// on the flat/opaque parts and may only differ in antialiased edge pixels.
func assertDiffBounded(t *testing.T, report comparisonReport) {
	for _, cmp := range report.Images {
		if !cmp.DimensionsSame {
			t.Errorf("%s/%s: size mismatch oracle %dx%d vs go %dx%d", cmp.Fixture, cmp.Kind, cmp.OracleWidth, cmp.OracleHeight, cmp.GoWidth, cmp.GoHeight)
			continue
		}
		if cmp.DiffRatio > 0.02 {
			t.Errorf("%s/%s: %.2f%% pixels differ (max diff %d), expected <= 2%%", cmp.Fixture, cmp.Kind, cmp.DiffRatio*100, cmp.MaxChannelDiff)
		}
		if cmp.MaxChannelDiff > 8 {
			t.Errorf("%s/%s: max channel diff %d, expected <= 8 (antialiasing/alpha ties only)", cmp.Fixture, cmp.Kind, cmp.MaxChannelDiff)
		}
		if cmp.Over8Pixels != 0 {
			t.Errorf("%s/%s: %d pixels differ by more than 8", cmp.Fixture, cmp.Kind, cmp.Over8Pixels)
		}
	}
}
