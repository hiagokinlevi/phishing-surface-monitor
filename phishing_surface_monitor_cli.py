import os
import click

from cli.scan import scan_command
from cli.ct_monitor import ct_monitor_command
from cli.dmarc import dmarc_check_command


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable ANSI colors/styling for plain-text terminal output.",
)
@click.pass_context
def main(ctx: click.Context, no_color: bool) -> None:
    """phishing-surface-monitor CLI."""
    ctx.ensure_object(dict)
    ctx.obj["no_color"] = no_color

    if no_color:
        os.environ["NO_COLOR"] = "1"


main.add_command(scan_command)
main.add_command(ct_monitor_command)
main.add_command(dmarc_check_command)


if __name__ == "__main__":
    main()
