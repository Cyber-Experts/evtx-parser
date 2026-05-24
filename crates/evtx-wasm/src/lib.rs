use std::io::Cursor;

use evtx::EvtxParser;
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::Serialize;
use wasm_bindgen::prelude::*;

const EVTX_MAGIC: &[u8] = b"ElfFile\x00";

#[derive(Serialize, Clone)]
struct EventRow {
    record_id: u64,
    timestamp: String,
    level: Option<u8>,
    event_id: Option<u32>,
    provider: Option<String>,
    channel: Option<String>,
    computer: Option<String>,
}

#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct EvtxHandle {
    rows: Vec<EventRow>,
    xmls: Vec<String>,
    event_data: Vec<Vec<(String, String)>>,
}

#[wasm_bindgen]
impl EvtxHandle {
    #[wasm_bindgen(constructor)]
    pub fn new(buffer: Vec<u8>) -> Result<EvtxHandle, JsValue> {
        if buffer.len() < 4096 {
            return Err(JsValue::from_str(
                "File is too small to be a Windows Event Log (need at least 4096 bytes).",
            ));
        }
        if &buffer[..EVTX_MAGIC.len()] != EVTX_MAGIC {
            return Err(JsValue::from_str(
                "Not an .evtx file: missing 'ElfFile' signature at offset 0.",
            ));
        }

        let mut parser = EvtxParser::from_read_seek(Cursor::new(buffer))
            .map_err(|e| JsValue::from_str(&format!("Failed to open EVTX: {e}")))?;

        let mut rows: Vec<EventRow> = Vec::new();
        let mut xmls: Vec<String> = Vec::new();
        let mut event_data: Vec<Vec<(String, String)>> = Vec::new();

        for record in parser.records() {
            let record = match record {
                Ok(r) => r,
                Err(_) => continue,
            };
            let row = extract_row(&record.data, record.event_record_id, &record.timestamp.to_rfc3339());
            let ed = parse_event_data(&record.data);
            rows.push(row);
            event_data.push(ed);
            xmls.push(record.data);
        }

        Ok(EvtxHandle { rows, xmls, event_data })
    }

    pub fn count(&self) -> u64 {
        self.rows.len() as u64
    }

    pub fn get_chunk(&self, start: u64, len: u64) -> Result<JsValue, JsValue> {
        let total = self.rows.len() as u64;
        let end = start.saturating_add(len).min(total);
        let slice = &self.rows[start as usize..end as usize];
        serde_wasm_bindgen::to_value(slice).map_err(|e| JsValue::from_str(&format!("{e}")))
    }

    pub fn get_xml(&self, index: u64) -> Result<String, JsValue> {
        self.xmls
            .get(index as usize)
            .cloned()
            .ok_or_else(|| JsValue::from_str("Record index out of bounds"))
    }

    pub fn get_event_data(&self, index: u64) -> Result<JsValue, JsValue> {
        let pairs = self
            .event_data
            .get(index as usize)
            .ok_or_else(|| JsValue::from_str("Record index out of bounds"))?;
        serde_wasm_bindgen::to_value(pairs).map_err(|e| JsValue::from_str(&format!("{e}")))
    }

    pub fn get_event_data_batch(&self, indices: Vec<u32>) -> Result<JsValue, JsValue> {
        let n = self.event_data.len();
        let empty: Vec<(String, String)> = Vec::new();
        let out: Vec<&Vec<(String, String)>> = indices
            .iter()
            .map(|&i| {
                let i = i as usize;
                if i < n {
                    &self.event_data[i]
                } else {
                    &empty
                }
            })
            .collect();
        serde_wasm_bindgen::to_value(&out).map_err(|e| JsValue::from_str(&format!("{e}")))
    }

    pub fn event_id_counts(&self) -> Result<JsValue, JsValue> {
        let mut counts: std::collections::HashMap<u32, u32> = std::collections::HashMap::new();
        for row in &self.rows {
            if let Some(id) = row.event_id {
                *counts.entry(id).or_insert(0) += 1;
            }
        }
        let mut pairs: Vec<(u32, u32)> = counts.into_iter().collect();
        pairs.sort_by(|a, b| b.1.cmp(&a.1));
        serde_wasm_bindgen::to_value(&pairs).map_err(|e| JsValue::from_str(&format!("{e}")))
    }
}

fn extract_row(xml: &str, record_id: u64, timestamp: &str) -> EventRow {
    EventRow {
        record_id,
        timestamp: timestamp.to_string(),
        level: extract_tag(xml, "<Level>", "</Level>").and_then(|s| s.parse().ok()),
        event_id: extract_event_id(xml),
        provider: extract_provider_name(xml),
        channel: extract_tag(xml, "<Channel>", "</Channel>").map(strip),
        computer: extract_tag(xml, "<Computer>", "</Computer>").map(strip),
    }
}

fn extract_tag(haystack: &str, open: &str, close: &str) -> Option<String> {
    let start = haystack.find(open)? + open.len();
    let rel_end = haystack[start..].find(close)?;
    Some(haystack[start..start + rel_end].to_string())
}

fn extract_event_id(xml: &str) -> Option<u32> {
    if let Some(plain) = extract_tag(xml, "<EventID>", "</EventID>") {
        let inner = plain.trim();
        return inner.parse().ok();
    }
    if let Some(open_pos) = xml.find("<EventID ") {
        let after = &xml[open_pos..];
        let body_start = after.find('>')? + 1;
        let body_end = after[body_start..].find("</EventID>")?;
        return after[body_start..body_start + body_end].trim().parse().ok();
    }
    None
}

fn extract_provider_name(xml: &str) -> Option<String> {
    let key = "<Provider ";
    let start = xml.find(key)? + key.len();
    let close = xml[start..].find('>')? + start;
    let attrs = &xml[start..close];
    let name_key = "Name=\"";
    let name_start = attrs.find(name_key)? + name_key.len();
    let name_end = attrs[name_start..].find('"')?;
    Some(attrs[name_start..name_start + name_end].to_string())
}

fn strip(s: String) -> String {
    s.trim().to_string()
}

// Flatten an Event record's <EventData> and/or <UserData> sections into an
// ordered list of (key, value) pairs. Mirrors the JS parseEventData that
// previously ran client-side at export time, but runs once at load.
//
// <EventData>
//   <Data Name="X">v</Data>     → ("X", "v")
//   <Data>v</Data>               → ("Data1", "v"), ("Data2", ...)
// </EventData>
//
// <UserData>
//   <SomeEvent xmlns="...">
//     <FieldA>v</FieldA>         → ("FieldA", "v")
//   </SomeEvent>
// </UserData>
fn parse_event_data(xml: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    #[derive(PartialEq)]
    enum Mode {
        Looking,
        EventData,
        UserData,
    }
    let mut mode = Mode::Looking;

    let mut unnamed: usize = 0;
    let mut current_name: Option<String> = None;
    let mut in_data: bool = false;
    let mut text_buf: String = String::new();

    // (local_name, had_child, text_so_far)
    let mut stack: Vec<(String, bool, String)> = Vec::new();

    let mut buf = Vec::new();
    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let local = local_name_string(&e);
                match mode {
                    Mode::Looking => {
                        if local == "EventData" {
                            mode = Mode::EventData;
                            unnamed = 0;
                        } else if local == "UserData" {
                            mode = Mode::UserData;
                            stack.clear();
                        }
                    }
                    Mode::EventData => {
                        if local == "Data" && !in_data {
                            let mut name_attr: Option<String> = None;
                            for attr in e.attributes().with_checks(false).flatten() {
                                if attr.key.local_name().as_ref() == b"Name" {
                                    if let Ok(v) = attr.unescape_value() {
                                        name_attr = Some(v.into_owned());
                                    }
                                }
                            }
                            if name_attr.is_none() {
                                unnamed += 1;
                                name_attr = Some(format!("Data{}", unnamed));
                            }
                            current_name = name_attr;
                            in_data = true;
                            text_buf.clear();
                        }
                    }
                    Mode::UserData => {
                        if let Some(top) = stack.last_mut() {
                            top.1 = true;
                        }
                        stack.push((local, false, String::new()));
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let local = local_name_string(&e);
                match mode {
                    Mode::EventData => {
                        if local == "Data" {
                            let mut name_attr: Option<String> = None;
                            for attr in e.attributes().with_checks(false).flatten() {
                                if attr.key.local_name().as_ref() == b"Name" {
                                    if let Ok(v) = attr.unescape_value() {
                                        name_attr = Some(v.into_owned());
                                    }
                                }
                            }
                            if name_attr.is_none() {
                                unnamed += 1;
                                name_attr = Some(format!("Data{}", unnamed));
                            }
                            if let Some(n) = name_attr {
                                out.push((n, String::new()));
                            }
                        }
                    }
                    Mode::UserData => {
                        if let Some(top) = stack.last_mut() {
                            top.1 = true;
                        }
                        // Self-closed element under UserData — treat as an empty-valued leaf.
                        out.push((local, String::new()));
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(t)) => match mode {
                Mode::EventData => {
                    if in_data {
                        if let Ok(s) = t.unescape() {
                            text_buf.push_str(&s);
                        }
                    }
                }
                Mode::UserData => {
                    if let Some(top) = stack.last_mut() {
                        if let Ok(s) = t.unescape() {
                            top.2.push_str(&s);
                        }
                    }
                }
                _ => {}
            },
            Ok(Event::CData(c)) => {
                if let Ok(s) = std::str::from_utf8(c.as_ref()) {
                    match mode {
                        Mode::EventData => {
                            if in_data {
                                text_buf.push_str(s);
                            }
                        }
                        Mode::UserData => {
                            if let Some(top) = stack.last_mut() {
                                top.2.push_str(s);
                            }
                        }
                        _ => {}
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name_string_end(&e);
                match mode {
                    Mode::EventData => {
                        if local == "Data" && in_data {
                            if let Some(n) = current_name.take() {
                                let v = text_buf.trim().to_string();
                                out.push((n, v));
                            }
                            in_data = false;
                            text_buf.clear();
                        } else if local == "EventData" {
                            mode = Mode::Looking;
                        }
                    }
                    Mode::UserData => {
                        if local == "UserData" {
                            mode = Mode::Looking;
                            stack.clear();
                        } else if let Some((n, had_child, text)) = stack.pop() {
                            if !had_child {
                                let v = text.trim().to_string();
                                if !v.is_empty() {
                                    out.push((n, v));
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    out
}

fn local_name_string(e: &quick_xml::events::BytesStart) -> String {
    let ln = e.local_name();
    std::str::from_utf8(ln.as_ref()).unwrap_or("").to_string()
}

fn local_name_string_end(e: &quick_xml::events::BytesEnd) -> String {
    let ln = e.local_name();
    std::str::from_utf8(ln.as_ref()).unwrap_or("").to_string()
}
