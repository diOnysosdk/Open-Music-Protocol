"""Generate deterministic, legally unencumbered WAV and FLAC fixtures.

The waveform is an integer triangle pattern authored for this test suite. WAV
uses only the Python standard library. FLAC output is pinned to SoundFile
0.14.0 / libsndfile 1.2.2; a different encoder version must not silently
replace the published bytes.
"""

import hashlib
import json
import pathlib
import wave

import soundfile
import numpy


ROOT = pathlib.Path(__file__).resolve().parents[1]
AUDIO = ROOT / "fixtures" / "audio"
SAMPLE_RATE = 8000
SAMPLE_COUNT = 2000


def samples():
    # Exactly representable signed PCM16 values; no floating-point oscillator.
    return [((index % 80) - 40) * 400 for index in range(SAMPLE_COUNT)]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if soundfile.__version__ != "0.14.0" or soundfile.__libsndfile_version__ != "1.2.2":
        raise RuntimeError("pinned SoundFile 0.14.0 / libsndfile 1.2.2 required")
    AUDIO.mkdir(parents=True, exist_ok=True)
    pcm = samples()

    wav_path = AUDIO / "omp-triangle-250ms.wav"
    with wave.open(str(wav_path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(SAMPLE_RATE)
        output.writeframes(b"".join(value.to_bytes(2, "little", signed=True) for value in pcm))

    flac_path = AUDIO / "omp-triangle-250ms.flac"
    soundfile.write(
        flac_path,
        numpy.asarray(pcm, dtype=numpy.int16),
        SAMPLE_RATE,
        format="FLAC",
        subtype="PCM_16",
    )

    entries = []
    for asset_id, path, media_type, rank in (
        ("primary-flac", flac_path, "audio/flac", 0),
        ("alternate-wav", wav_path, "audio/wav", 10),
    ):
        entries.append({
            "asset_id": asset_id,
            "relative_path": f"audio/{path.name}",
            "media_type": media_type,
            "sha256": sha256(path),
            "size_bytes": path.stat().st_size,
            "selection_rank": rank,
        })

    index = {
        "profile": "OMP-v0.2-audio-fixtures-1",
        "license": "CC0-1.0",
        "generator": {
            "python_wave": "standard-library",
            "soundfile": soundfile.__version__,
            "libsndfile": soundfile.__libsndfile_version__,
            "numpy": numpy.__version__,
        },
        "pcm": {
            "sample_rate": SAMPLE_RATE,
            "channels": 1,
            "bits_per_sample": 16,
            "sample_count": SAMPLE_COUNT,
            "duration_ms": 250,
            "definition": "sample[n] = ((n mod 80) - 40) * 400"
        },
        "assets": entries,
    }
    (AUDIO / "fixture-index.json").write_text(
        json.dumps(index, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()

