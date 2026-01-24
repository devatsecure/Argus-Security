#!/usr/bin/env python3
"""
Sample Python CLI Tool - NOT a web application
This is a command-line tool that outputs to terminal
XSS findings in print() or logging.info() should be FALSE POSITIVES
"""

import logging
import sys
from typing import Optional

import click
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Test Python CLI Tool"""
    pass


@cli.command()
@click.argument('script')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
def run(script: str, verbose: bool):
    """Run a script with user input

    POTENTIAL FALSE POSITIVE: This uses logging.info() and print() for terminal output
    These are NOT XSS vulnerabilities - they output to terminal, not browser DOM
    """
    # Terminal logging - NOT XSS (outputs to console, not HTML)
    logger.info(f"Running script: {script}")

    if verbose:
        # Terminal print - NOT XSS
        print(f"{Fore.GREEN}Executing: {script}{Style.RESET_ALL}")

    # Another potential false positive - string formatting for terminal
    output = f"Script output: {script}"
    print(output)


@cli.command()
@click.argument('message')
@click.option('--color', default='white', help='Output color')
def display(message: str, color: str):
    """Display a message to terminal

    POTENTIAL FALSE POSITIVE: Terminal output with user data
    Not XSS because it's command-line, not web browser
    """
    color_map = {
        'red': Fore.RED,
        'green': Fore.GREEN,
        'blue': Fore.BLUE,
        'yellow': Fore.YELLOW,
        'white': Fore.WHITE,
    }

    selected_color = color_map.get(color.lower(), Fore.WHITE)

    # Terminal output - NOT XSS
    print(f"{selected_color}Message: {message}{Style.RESET_ALL}")


@cli.command()
@click.argument('data')
@click.option('--format', type=click.Choice(['text', 'json']), default='text')
def log(data: str, format: str):
    """Log data to terminal

    POTENTIAL FALSE POSITIVE: Logging user data
    This is terminal logging, not web output
    """
    if format == 'json':
        import json
        output = json.dumps({'data': data})
        print(output)
    else:
        # Terminal logging - NOT XSS
        logger.info(f"[LOG] {data}")
        print(f"[LOG] {data}")


@cli.command()
@click.argument('user_input')
def process(user_input: str):
    """Process user input and display results

    POTENTIAL FALSE POSITIVE: All output is to terminal/logs
    """
    # These are all terminal outputs, NOT browser DOM manipulation
    logger.debug(f"Processing input: {user_input}")
    result = f"Processed: {user_input.upper()}"
    logger.info(result)
    print(result)


if __name__ == '__main__':
    cli()
