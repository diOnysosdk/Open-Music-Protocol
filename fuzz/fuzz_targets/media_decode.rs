#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use symphonia::core::{
    codecs::DecoderOptions, errors::Error, formats::FormatOptions, io::MediaSourceStream,
    meta::MetadataOptions, probe::Hint,
};

fuzz_target!(|data: &[u8]| {
    // Bound memory independently from libFuzzer's evolving maximum input.
    let bytes = data[..data.len().min(8 * 1024 * 1024)].to_vec();
    for extension in ["wav", "flac"] {
        let stream =
            MediaSourceStream::new(Box::new(Cursor::new(bytes.clone())), Default::default());
        let mut hint = Hint::new();
        hint.with_extension(extension);
        let Ok(probed) = symphonia::default::get_probe().format(
            &hint,
            stream,
            &FormatOptions::default(),
            &MetadataOptions::default(),
        ) else {
            continue;
        };
        let mut format = probed.format;
        let Some(track) = format.default_track() else {
            continue;
        };
        let track_id = track.id;
        let Ok(mut decoder) =
            symphonia::default::get_codecs().make(&track.codec_params, &DecoderOptions::default())
        else {
            continue;
        };
        let mut packets = 0_u64;
        let mut frames = 0_u64;
        while packets < 256 && frames < 2_000_000 {
            let packet = match format.next_packet() {
                Ok(packet) => packet,
                Err(Error::IoError(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(_) => break,
            };
            if packet.track_id() != track_id {
                continue;
            }
            packets += 1;
            match decoder.decode(&packet) {
                Ok(decoded) => frames = frames.saturating_add(decoded.frames() as u64),
                Err(_) => break,
            }
        }
    }
});
