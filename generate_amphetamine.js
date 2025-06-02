#!/usr/bin/env node
const fs = require('fs');
const { spawnSync, spawn } = require('child_process');
const yargs = require('yargs');
const wavDecoder = require('node-wav');
const wavEncoder = require('wav-encoder');
const say = require('say');
const DSP = require('dsp.js').DSP;

const FS_DEFAULT = 44100;
const PRESET_FS = [8000, 16000, 22050, 44100];
const ANXIETY_CUTOFF = 2000.0;

function lowPassFilter(audio, fs, cutoff) {
  const filter = new DSP.IIRFilter(DSP.LOWPASS, cutoff / (fs / 2), 4);
  return audio.map(sample => filter.process(sample));
}

function generateAmphetamineSignal(duration, fs, cutoff) {
  const len = Math.floor(duration * fs);
  const t = Array.from({ length: len }, (_, i) => i / fs);
  const noise = Array.from({ length: len }, () => Math.random() * 2 - 1);
  const filteredNoise = lowPassFilter(noise, fs, cutoff);
  const freqs = Array.from({ length: 3 }, () => Math.random() * 15 + 5);
  const env = t.map(time =>
    freqs.reduce((acc, f) => acc + (Math.sin(2 * Math.PI * f * time) + 1) / 2, 0) /
      freqs.length
  );
  const modulated = filteredNoise.map((v, i) => v * env[i]);
  const finalFilt = lowPassFilter(modulated, fs, ANXIETY_CUTOFF);
  const maxAmp = Math.max(...finalFilt.map(Math.abs));
  return finalFilt.map(v => v / maxAmp);
}

function ttsToAudio(text, fs) {
  return new Promise((resolve, reject) => {
    const tmp = 'temp_tts.wav';
    say.export(text, null, 1.0, tmp, err => {
      if (err) return reject(err);
      const buffer = fs.readFileSync(tmp);
      const result = wavDecoder.decode(buffer);
      let audio = result.channelData[0];
      if (result.sampleRate !== fs) {
        spawnSync('ffmpeg', ['-y', '-i', tmp, '-ar', String(fs), 'temp_tts_resampled.wav']);
        const buf2 = fs.readFileSync('temp_tts_resampled.wav');
        const res2 = wavDecoder.decode(buf2);
        audio = res2.channelData[0];
      }
      resolve(audio);
    });
  });
}

async function main() {
  const argv = yargs
    .option('text', { type: 'string', demandOption: true })
    .option('cutoff', { type: 'number', default: 3000.0 })
    .option('fs', { type: 'number', choices: PRESET_FS, default: FS_DEFAULT })
    .argv;

  const fsamp = argv.fs;
  const cutoff = argv.cutoff;
  console.log(`[DEBUG] FS=${fsamp}, cutoff=${cutoff}`);
  console.log('[DEBUG] Converting text to audio');
  const ttsAudio = await ttsToAudio(argv.text, fsamp);
  const duration = ttsAudio.length / fsamp;
  console.log(`[DEBUG] TTS duration=${duration.toFixed(2)}s`);

  console.log('[DEBUG] Generating amphetamine signal');
  const amphet = generateAmphetamineSignal(duration, fsamp, cutoff);

  console.log('[DEBUG] Combining audio and filtering');
  const combined = ttsAudio.map((v, i) => (v + amphet[i]) / 2);
  const outAudio = lowPassFilter(combined, fsamp, ANXIETY_CUTOFF);

  const audioFile = 'temp_out.wav';
  const encoded = await wavEncoder.encode({ sampleRate: fsamp, channelData: [outAudio] });
  fs.writeFileSync(audioFile, Buffer.from(encoded));
  console.log(`[DEBUG] Wrote audio file ${audioFile}`);

  console.log('[DEBUG] Creating video clip');
  spawnSync('ffmpeg', [
    '-y',
    '-f',
    'lavfi',
    '-i',
    `color=c=black:s=640x480:d=${duration}`,
    '-i',
    audioFile,
    '-c:v',
    'libx264',
    '-r',
    '24',
    '-c:a',
    'aac',
    'output.mp4'
  ]);
  console.log('[DEBUG] Video generation complete');

  console.log('[DEBUG] Starting playback loop');
  const player = spawn('ffplay', ['-autoexit', '-loop', '0', 'output.mp4'], { stdio: 'inherit' });
  player.on('close', (code, signal) => {
    if (signal === 'SIGINT') console.log('[DEBUG] Playback interrupted');
  });
}

if (require.main === module) {
  main().catch(err => console.error(err));
}
