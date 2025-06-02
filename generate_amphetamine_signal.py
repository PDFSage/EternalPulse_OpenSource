#!/usr/bin/env python3
import argparse
import os
import numpy as np
import scipy.signal
import soundfile as sf
import pyttsx3
import subprocess

FS_DEFAULT = 44100
PRESET_FS = [8000, 16000, 22050, 44100]
ANXIETY_CUTOFF = 2000.0

def low_pass_filter(audio, fs, cutoff):
    b, a = scipy.signal.butter(4, cutoff/(fs/2), btype='low')
    return scipy.signal.lfilter(b, a, audio)

def generate_amphetamine_signal(duration, fs, cutoff):
    t = np.linspace(0, duration, int(duration * fs), endpoint=False)
    noise = np.random.randn(len(t))
    filtered = low_pass_filter(noise, fs, cutoff)
    freqs = np.random.uniform(5, 20, 3)
    env = np.mean([(np.sin(2 * np.pi * f * t) + 1) / 2 for f in freqs], axis=0)
    sig = filtered * env
    sig = low_pass_filter(sig, fs, ANXIETY_CUTOFF)
    return sig / np.max(np.abs(sig))

def tts_to_audio(text, fs):
    tmp = 'temp_tts.wav'
    engine = pyttsx3.init()
    engine.save_to_file(text, tmp)
    engine.runAndWait()
    audio, orig_fs = sf.read(tmp)
    if orig_fs != fs:
        audio = scipy.signal.resample(audio, int(len(audio) * fs / orig_fs))
    return audio

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--text', required=True)
    parser.add_argument('--cutoff', type=float, default=3000.0)
    parser.add_argument('--fs', type=int, choices=PRESET_FS, default=FS_DEFAULT)
    args = parser.parse_args()

    fs = args.fs
    cutoff = args.cutoff
    print(f"[DEBUG] FS={fs}, cutoff={cutoff}")
    print("[DEBUG] Converting text to audio")
    tts_audio = tts_to_audio(args.text, fs)
    duration = len(tts_audio) / fs
    print(f"[DEBUG] TTS duration={duration:.2f}s")

    print("[DEBUG] Generating amphetamine signal")
    amphet = generate_amphetamine_signal(duration, fs, cutoff)

    print("[DEBUG] Combining audio and filtering")
    combined = (tts_audio + amphet) / 2
    out = low_pass_filter(combined, fs, ANXIETY_CUTOFF)

    audio_file = 'temp_out.wav'
    sf.write(audio_file, out, fs)
    print(f"[DEBUG] Wrote audio file {audio_file}")

    print("[DEBUG] Creating video via ffmpeg")
    # use ffmpeg to generate a black video with audio
    subprocess.run([
        'ffmpeg', '-y',
        '-f', 'lavfi', '-i', f"color=size=640x480:duration={duration}:rate=24:color=black",
        '-i', audio_file,
        '-c:v', 'libx264', '-c:a', 'aac',
        '-shortest', 'output.mp4'
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[DEBUG] Video generation complete")

    print("[DEBUG] Starting playback loop")
    try:
        subprocess.run(['ffplay', '-autoexit', '-loop', '0', 'output.mp4'])
    except KeyboardInterrupt:
        print("[DEBUG] Playback interrupted")

if __name__ == '__main__':
    main()
