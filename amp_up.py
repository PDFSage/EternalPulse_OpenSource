#!/usr/bin/env python3
import sys
import subprocess

def main(input_path, output_path,
         speed=1.3, pitch_factor=1.05,
         hp_cutoff=300, lp_cutoff=3400):
    # bandpass for typical human voice range
    filters = [
        f"asetrate=44100*{pitch_factor}",
        "aresample=44100",
        f"atempo={speed}",
        "acompressor=threshold=-20dB:ratio=4:attack=20:release=100",
        f"highpass=f={hp_cutoff}",
        f"lowpass=f={lp_cutoff}",
        "volume=1.5"
    ]
    filt_chain = ",".join(filters)
    cmd = [
        "ffmpeg", "-y", "-i", input_path,
        "-filter:a", filt_chain,
        "-c:v", "copy", "-c:a", "aac",
        output_path
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if proc.returncode != 0:
        print(proc.stderr)
        sys.exit(proc.returncode)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_video> <output_video>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
