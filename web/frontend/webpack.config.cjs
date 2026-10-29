const path = require('path')
const webpack = require('webpack')
const MiniCssExtractPlugin = require('mini-css-extract-plugin')
const CssMinimizerPlugin = require('css-minimizer-webpack-plugin')

class ManifestPlugin {
  apply(compiler) {
    compiler.hooks.thisCompilation.tap('Manifest', compilation => {
      compilation.hooks.processAssets.tap({name:'Manifest',stage:webpack.Compilation.PROCESS_ASSETS_STAGE_REPORT}, () => {
        const entries = Object.fromEntries([...compilation.entrypoints].map(([name, entry]) => [name, entry.getFiles()]))
        compilation.emitAsset('manifest.json', new webpack.sources.RawSource(JSON.stringify(entries, null, 2)))
      })
    })
  }
}

module.exports = {
  mode: 'production',
  entry: {
    app: ['react-hot-loader/patch', '@/index.tsx'],
    style: ['@/styles/common.css','admin-lte/dist/css/alt/adminlte.components.min.css','admin-lte/dist/css/alt/adminlte.core.min.css','admin-lte/dist/css/alt/adminlte.pages.min.css','admin-lte/dist/css/alt/adminlte.light.min.css'],
    meta: '@/scripts/meta.ts', sw: '@/scripts/sw.ts',
    home: '@/scripts/homePage.ts', 'home-css': '@/styles/home.css',
    spectre: ['spectre.css/dist/spectre.min.css','@/fonts/minecraft.css','@/styles/spectre.css'],
  },
  output: { path:path.resolve(__dirname,'../static/app'),publicPath:'auto',filename:'[name].[contenthash:7].js',chunkFilename:'[id].[contenthash:7].js',crossOriginLoading:'anonymous',clean:true },
  module: { rules: [
    {test:/\.tsx?$/,loader:'ts-loader',options:{configFile:'tsconfig.build.json',transpileOnly:true}},
    {test:/\.css$/,use:[MiniCssExtractPlugin.loader,{loader:'css-loader',options:{importLoaders:1}},'postcss-loader']},
    {test:/\.(png|webp|svg|woff2?|eot|ttf)$/,type:'asset'},
  ]},
  plugins: [new MiniCssExtractPlugin({filename:'[name].[contenthash:7].css',chunkFilename:'[id].[contenthash:7].css'}),new ManifestPlugin(),new webpack.DefinePlugin({'window.Deno':'true',Deno:{args:[],build:{},version:{}},'process.platform':'"browser"',__blessing_public_path__:JSON.stringify('/app/')})],
  resolve:{extensions:['.js','.ts','.tsx'],alias:{'react-dom':'@hot-loader/react-dom','@':path.resolve(__dirname,'resources/assets/src'),readline:'@/scripts/cli/readline.ts',prompts:'prompts/lib/index.js',assert:false}},
  optimization:{minimizer:[new CssMinimizerPlugin({}),'...']},
  experiments:{syncWebAssembly:true},
  stats:'errors-warnings',ignoreWarnings:[/size limit/i],
}
