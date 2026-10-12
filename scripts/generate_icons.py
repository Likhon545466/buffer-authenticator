import os
import subprocess
import tempfile
from PIL import Image

def generate_icons():
    svg_content = '''<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="bgGrad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#004a77"/>
      <stop offset="100%" stop-color="#002d4c"/>
    </linearGradient>
  </defs>
  <!-- Squircle rounded badge -->
  <rect x="24" y="24" width="464" height="464" rx="140" ry="140" 
        fill="url(#bgGrad)" 
        stroke="rgba(168, 199, 250, 0.35)" 
        stroke-width="12"/>
  <!-- Outline shield icon -->
  <g transform="translate(136, 136) scale(10)">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" 
          fill="none" 
          stroke="#a8c7fa" 
          stroke-width="1.9" 
          stroke-linecap="round" 
          stroke-linejoin="round"/>
  </g>
</svg>'''

    with tempfile.NamedTemporaryFile(suffix='.svg', delete=False, mode='w') as f:
        f.write(svg_content)
        svg_path = f.name

    png_path = svg_path.replace('.svg', '.png')

    try:
        subprocess.run([
            'google-chrome',
            '--headless',
            '--disable-gpu',
            '--default-background-color=00000000',
            f'--screenshot={png_path}',
            '--window-size=512,512',
            svg_path
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        src = Image.open(png_path)
        os.makedirs('icons', exist_ok=True)
        for sz in [128, 48, 16]:
            resized = src.resize((sz, sz), Image.Resampling.LANCZOS)
            out_path1 = f'icons/icon-{sz}.png'
            out_path2 = f'icons/buffer-icon-{sz}.png'
            resized.save(out_path1, format='PNG')
            resized.save(out_path2, format='PNG')
            print(f'Generated {out_path1} and {out_path2} ({sz}x{sz})')
    finally:
        if os.path.exists(svg_path):
            os.remove(svg_path)
        if os.path.exists(png_path):
            os.remove(png_path)

if __name__ == '__main__':
    generate_icons()
