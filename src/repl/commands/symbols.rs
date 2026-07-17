use crate::error::Result;
use crate::expr::Expr;
use crate::symbols::format_symbol_with_offset;
use crate::target::UserVar;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_x;
    names: ["x"],
    usage: "x <query>  or  x <module>!<query>",
    summary: "Fuzzy-search symbols by name.",
    details: "operators: ^prefix  suffix$  'exact  !negate  (space = AND)",
    completion: Symbol,
}

repl_command! {
    cmd_ln;
    names: ["ln"],
    usage: "ln <address>",
    summary: "List the nearest symbol to an address.",
    completion: Expression,
}

repl_command! {
    cmd_ev;
    names: ["ev", "?"],
    usage: "ev <expression>",
    summary: "Evaluate an expression.",
    completion: Expression,
    style: ExpressionTail,
}

repl_command! {
    cmd_set;
    names: ["set"],
    usage: "set $<name> <expression>",
    summary: "Define a convenience variable usable in expressions as $<name>.",
    completion: [None, Expression],
}

repl_command! {
    cmd_vars();
    names: ["vars"],
    usage: "vars",
    summary: "List defined convenience variables and result slots.",
}

repl_command! {
    cmd_unset;
    names: ["unset"],
    usage: "unset $<name>",
    summary: "Remove a convenience variable.",
}

impl ReplState<'_> {
    fn cmd_x(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(query) = invocation.arg(0) else {
            println!("{}\n", command_help("x"));
            return Ok(());
        };
        // bounded purely for terminal-output sanity (resolution
        // is O(1) now); a huge match set just floods the screen
        const X_LIMIT: usize = 4096;
        let dtb = self.ctx.target.current_dtb();
        // `module!query` scopes the search to one module; a bare
        // query fuzzy-matches across the cached merged index
        let (module_filter, names) = match query.split_once('!') {
            Some((module, q)) => (
                Some(module),
                self.ctx
                    .target
                    .symbols
                    .search_symbols_in_module(dtb, module, q, X_LIMIT),
            ),
            None => (
                None,
                self.caches.symbols.read().unwrap().search(query, X_LIMIT),
            ),
        };
        let truncated = names.len() >= X_LIMIT;
        let mut hits: Vec<u64> = Vec::new();
        for name in &names {
            // resolve within the requested module when scoped,
            // so a name present in several modules isn't hijacked
            let lookup = match module_filter {
                Some(m) => format!("{}!{}", m, name),
                None => name.clone(),
            };
            if let Some((addr, module)) = self
                .ctx
                .target
                .symbols
                .find_symbol_with_module(dtb, &lookup)
            {
                println!(
                    "{}  {}",
                    ui::addr(addr.0),
                    ui::symbol(&format!("{}!{}", module, name))
                );
                hits.push(addr.0);
            }
        }
        if hits.is_empty() {
            println!("no symbols match '{}'", query);
        } else {
            println!(
                "\n{} {}{} (in $0..${})",
                hits.len(),
                if hits.len() == 1 { "symbol" } else { "symbols" },
                if truncated {
                    ", truncated; refine query"
                } else {
                    ""
                },
                hits.len() - 1
            );
        }
        self.ctx.target.set_results(hits, self.line.clone());
        println!();

        Ok(())
    }

    fn cmd_ln(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(arg) = invocation.arg(0) else {
            println!("{}\n", command_help("ln"));
            return Ok(());
        };
        let addr = match Expr::eval(arg, &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        match self
            .ctx
            .target
            .symbols
            .find_closest_symbol_for_address(self.ctx.target.current_dtb(), addr)
        {
            Some((module, sym, offset)) => {
                let label = format_symbol_with_offset(&module, &sym, offset);
                println!("{}  {}\n", ui::addr(addr.0), ui::symbol(&label));
                // $0 = the symbol's base address (the resolved target)
                self.ctx
                    .target
                    .set_results(vec![(addr - offset as u64).0], self.line.clone());
            }
            None => {
                println!("no symbol found for {}\n", ui::addr(addr.0));
            }
        }

        Ok(())
    }

    fn cmd_ev(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let expr_str = invocation.raw_tail;
        if expr_str.is_empty() {
            println!("{}\n", command_help("ev"));
            return Ok(());
        }

        match Expr::eval(expr_str, &self.ctx.target) {
            Ok(addr) => {
                self.ctx.target.set_results(vec![addr.0], self.line.clone());
                println!("{}", ui::addr(addr.0));
            }
            Err(e) => error!("{}", e),
        }

        Ok(())
    }

    fn cmd_set(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let rest = invocation.join_args(0);
        let Some((lhs, rhs)) = rest.split_once(char::is_whitespace) else {
            println!("{}\n", command_help("set"));
            return Ok(());
        };
        let name = lhs.trim().strip_prefix('$').unwrap_or(lhs.trim()).trim();
        // names must start with a letter or '_'; this reserves
        // $<digits> (and digit-leading names) for the $0..$N
        // result slots, avoiding any collision
        let valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            error!(
                "invalid variable name '${}' (must start with a letter or '_'; $<digits> are reserved for result slots)",
                name
            );
            return Ok(());
        }
        let source = rhs.trim().to_string();
        match Expr::eval(&source, &self.ctx.target) {
            Ok(v) => {
                self.ctx
                    .target
                    .user_vars
                    .insert(name.to_string(), UserVar { value: v.0, source });
                println!("${} = {}\n", name, ui::addr(v.0));
            }
            Err(e) => error!("{}", e),
        }

        Ok(())
    }

    fn cmd_vars(&mut self) -> Result<()> {
        let builtins = self.ctx.target.builtin_variables();
        if self.ctx.target.user_vars.is_empty()
            && self.ctx.target.results.is_empty()
            && builtins.is_empty()
        {
            println!("no variables defined\n");
            return Ok(());
        }
        let mut names: Vec<&String> = self.ctx.target.user_vars.keys().collect();
        names.sort();
        if !names.is_empty() {
            println!("{}", ui::label("user"));
            for name in names {
                let var = &self.ctx.target.user_vars[name];
                println!(
                    "  ${:<16} {}   {}",
                    name,
                    ui::addr(var.value),
                    ui::muted(&var.source)
                );
            }
        }
        if !self.ctx.target.results.is_empty() {
            if !self.ctx.target.user_vars.is_empty() {
                println!();
            }
            let origin = self
                .ctx
                .target
                .results_origin
                .as_deref()
                .map(|cmd| format!("from: {}", cmd))
                .unwrap_or_default();
            println!(
                "  {}   {}",
                ui::muted(&format!("$0..${}", self.ctx.target.results.len() - 1)),
                ui::muted(&origin)
            );
        }
        if !builtins.is_empty() {
            if !self.ctx.target.user_vars.is_empty() || !self.ctx.target.results.is_empty() {
                println!();
            }
            println!("{}", ui::label("builtins"));
            for var in builtins {
                println!(
                    "  ${:<16} {}   {}",
                    var.name,
                    ui::addr(var.value),
                    ui::muted(var.source)
                );
            }
        }
        println!();

        Ok(())
    }

    fn cmd_unset(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(arg) = invocation.arg(0) else {
            println!("{}\n", command_help("unset"));
            return Ok(());
        };
        let name = arg.strip_prefix('$').unwrap_or(arg);
        if self.ctx.target.user_vars.remove(name).is_some() {
            println!("unset ${}\n", name);
        } else {
            error!("no such variable: ${}", name);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::repl::{CommandStyle, parse_command};

    #[test]
    fn ev_keeps_expression_tail() {
        let parsed = parse_command("ev rax + rbx").unwrap().unwrap();
        let invocation = parsed.invocation(CommandStyle::ExpressionTail).unwrap();
        assert_eq!(invocation.raw_tail, "rax + rbx");
        assert!(invocation.argv.is_empty());
    }
}
