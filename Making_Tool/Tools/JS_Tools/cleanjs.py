import subprocess
from pathlib import Path

def run_clean_js_tool():
    print('run clean js')

    script = """
    const fs = require('fs');
    const path = require('path');
    const { execSync } = require('child_process');

    const inputDir = './input_js';
    const outputDir = './output_js';

    if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
    }

    const files = fs.readdirSync(inputDir).filter(file => {
        // filtering (Source Maps)
        if (file.endsWith('.js.map')) return false;
        // just js files...
        return file.endsWith('.js');
    });

    files.forEach(file => {
        const inputPath = path.join(inputDir, file);
        const baseName = path.basename(file, '.js');
        const outputFileName = `${baseName}_clean.js`;
        const outputPath = path.join(outputDir, outputFileName);

        // read file... (Obfuscation)
        const content = fs.readFileSync(inputPath, 'utf8');
        
        // simple check for JSFuck...
        const jsFuckRegex = /^[()[\]!+]+$/;
        const cleanContent = content.replace(/\s/g, ''); // for check...
        if (cleanContent.length > 20 && jsFuckRegex.test(cleanContent)) {
            console.log(`[*] dont accept (JSFuck): ${file}`);
            return; // dont processing
        }

        console.log(`[-] processing: ${file} ...`);

        try {
            // dont give this tool brainfuck or jsfuck files.
            execSync(`npx prettier --parser babel "${inputPath}" > "${outputPath}"`, { stdio: 'inherit' });
            console.log(`[~] save (: ${outputFileName}\n`);
        } catch (err) {
            console.error(`[*] error ${file} (anknow syntask for Prettier ): `);
        }
    });
    """
    path = Path('script.js')
    path.write_text(script,encoding='utf-8')
    subprocess.run(['node'], ['script.js'])
