use iced_x86::{
    Code, Decoder, DecoderOptions, Formatter, FormatterOutput, FormatterTextKind, Instruction,
    MemorySizeOptions, NasmFormatter,
};

/// NASM formatter configured for ntoseye's disassembly, so every call site
/// decodes identically.
pub fn disasm_formatter() -> NasmFormatter {
    let mut formatter = NasmFormatter::new();
    let options = formatter.options_mut();
    options.set_space_after_operand_separator(true);
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_first_operand_char_index(5);
    options.set_memory_size_options(MemorySizeOptions::Always);
    options.set_show_branch_size(false);
    options.set_rip_relative_addresses(true);
    formatter
}

/// A semantic classification for one disassembly token, assigned by the
/// decoder and turned into color by the presentation layer. Color-agnostic on
/// purpose: core decodes, `ui` owns the palette.
#[derive(Clone, Copy)]
pub enum AsmKind {
    Mnemonic,
    Register,
    Number,
    Punctuation,
    Keyword,
    Text,
}

/// One formatted token of an instruction: its text and semantic kind.
pub struct AsmToken {
    pub text: String,
    pub kind: AsmKind,
}

/// Collects iced's formatter output into semantic [`AsmToken`]s, mapping the
/// formatter's fine-grained kinds onto our small render palette.
struct TokenSink<'a>(&'a mut Vec<AsmToken>);

impl FormatterOutput for TokenSink<'_> {
    fn write(&mut self, text: &str, kind: FormatterTextKind) {
        let kind = match kind {
            FormatterTextKind::Mnemonic | FormatterTextKind::Prefix => AsmKind::Mnemonic,
            FormatterTextKind::Register => AsmKind::Register,
            FormatterTextKind::Number
            | FormatterTextKind::LabelAddress
            | FormatterTextKind::FunctionAddress
            | FormatterTextKind::SelectorValue => AsmKind::Number,
            FormatterTextKind::Punctuation | FormatterTextKind::Operator => AsmKind::Punctuation,
            FormatterTextKind::Keyword
            | FormatterTextKind::Directive
            | FormatterTextKind::Decorator => AsmKind::Keyword,
            _ => AsmKind::Text,
        };
        self.0.push(AsmToken {
            text: text.to_string(),
            kind,
        });
    }
}

/// One decoded instruction, ready to render: address, space-joined hex bytes,
/// the asm as semantic [`AsmToken`]s, and an optional symbol comment for a
/// branch / rip-relative target.
pub struct DisasmRow {
    pub ip: u64,
    pub hex: String,
    pub tokens: Vec<AsmToken>,
    pub comment: Option<String>,
}

impl DisasmRow {
    /// The instruction as plain, unstyled text — the form MCP, the Python
    /// binding, and JSON output consume. Colored rendering goes through
    /// `ui::disasm_asm` instead.
    pub fn asm(&self) -> String {
        self.tokens.iter().map(|t| t.text.as_str()).collect()
    }
}

/// Decode `bytes` (loaded at `start_addr`) into rows, stopping after `limit`
/// instructions when `Some`. `resolve` turns a branch / rip-relative target
/// into a symbol comment. The caller owns `formatter` (build it once with
/// [`disasm_formatter`]) so it's reused across decode passes.
pub fn decode_rows(
    bytes: &[u8],
    start_addr: u64,
    limit: Option<usize>,
    formatter: &mut NasmFormatter,
    resolve: impl Fn(u64) -> String,
) -> Vec<DisasmRow> {
    let mut decoder = Decoder::with_ip(64, bytes, start_addr, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    let mut rows = Vec::new();

    while decoder.can_decode() && limit.is_none_or(|n| rows.len() < n) {
        decoder.decode_out(&mut instruction);
        if instruction.code() == Code::INVALID {
            continue;
        }
        let mut tokens = Vec::new();
        formatter.format(&instruction, &mut TokenSink(&mut tokens));

        let ip = instruction.ip();
        let start_index = (ip - start_addr) as usize;
        let instr_bytes = &bytes[start_index..start_index + instruction.len()];
        let hex = instr_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let comment = if instruction.is_ip_rel_memory_operand() {
            Some(resolve(instruction.ip_rel_memory_address()))
        } else if instruction.is_call_near()
            || instruction.is_jmp_near()
            || instruction.is_jcc_near()
        {
            Some(resolve(instruction.near_branch_target()))
        } else {
            None
        };

        rows.push(DisasmRow {
            ip,
            hex,
            tokens,
            comment,
        });
    }

    rows
}
