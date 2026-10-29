const fs = require('fs')
const path = require('path')
const yaml = require('js-yaml')
const root = path.resolve(__dirname, '..')
const output = path.join(root, '../static/lang')
fs.mkdirSync(output, {recursive:true})
for (const locale of fs.readdirSync(path.join(root,'resources/lang')).sort()) {
  const directory=path.join(root,'resources/lang',locale)
  if (!fs.statSync(directory).isDirectory()) continue
  const messages={}
  for (const file of fs.readdirSync(directory).filter(x=>x.endsWith('.yml')).sort()) {
    messages[file.slice(0,-4)]=yaml.safeLoad(fs.readFileSync(path.join(directory,file),'utf8'))
  }
  fs.writeFileSync(path.join(output,`${locale}.json`), JSON.stringify(messages))
}
