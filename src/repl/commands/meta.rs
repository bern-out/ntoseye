use crate::error::Result;
#[cfg(feature = "python")]
use crate::python::embed;

use crate::repl::*;

repl_command! {
    cmd_reload();
    names: ["reload"],
    usage: "reload",
    summary: "Reload custom commands and aliases.",
}

repl_command! {
    names: ["quit", "q"],
    usage: "quit",
    summary: "Exit the application.",
    flow: Quit,
}

impl ReplState<'_> {
    fn cmd_reload(&mut self) -> Result<()> {
        #[cfg(feature = "python")]
        {
            let py_report = embed::load_commands_dir();
            embed::print_script_load_report(&py_report);
            *self.caches.user_commands.write().unwrap() = initial_user_commands();
        }
        let alias_report = self.reload_aliases();
        print_alias_load_report(&alias_report);
        Ok(())
    }

    pub fn cmd_user(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        #[cfg(feature = "python")]
        if embed::has_command(invocation.name) {
            let args: Vec<&str> = invocation.argv.iter().map(|arg| arg.as_ref()).collect();
            if let Err(e) = embed::dispatch(invocation.name, &args, self.ctx) {
                error!("{}: {}", invocation.name, e);
            }
            return Ok(());
        }

        println!(
            "unknown command: '{}' (try pressing tab to see available commands)\n",
            invocation.name
        );

        Ok(())
    }
}
