package modules

import "context"

// PluginData mirrors the original getPluginData() response field for field.
type PluginData struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
	Enabled     bool   `json:"enabled"`
	Config      bool   `json:"config"`
	Readme      bool   `json:"readme"`
	Icon        Icon   `json:"icon"`
}

// Icon merges the fixed defaults with the frozen manifest icon attr; the
// original returns faType fas for every supported module.
type Icon struct {
	Fa     string `json:"fa"`
	FaType string `json:"faType"`
	Bg     string `json:"bg"`
}

// Installed lists the registered module cards with their enable facts in the
// original display order, resolved for the request locale. Unregistered names
// stay absent exactly like the original directory scan after a deletion.
func (m *Manager) Installed(ctx context.Context, locale string, state *State) []PluginData {
	values := make([]PluginData, 0, len(fixed))
	for _, meta := range fixed {
		if !state.HasInstalled(meta.Name) {
			continue
		}
		title, description := meta.Translations(locale)
		data := PluginData{
			Name:        meta.Name,
			Title:       title,
			Description: description,
			Version:     meta.Version,
			Enabled:     state.HasEnabled(meta.Name),
			Config:      meta.Config,
			Readme:      meta.Readme,
			Icon:        Icon{Fa: meta.IconFa, FaType: "fas", Bg: meta.IconBg},
		}
		values = append(values, data)
	}
	return values
}
