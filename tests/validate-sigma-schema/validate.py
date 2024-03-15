#!/usr/bin/env python3

import os
import sys
import requests
import warnings

from pathlib import Path
from typing import Any, Dict, Iterator, List, NoReturn


def get_envs() -> Dict[str, Any]:
    """Normalize the environment variables used by the action and returns them as a dictionary.

    Returns:
        Dict[str, Any]: A dictionary containing the environment variables used by the action.
    """

    github_workspace = Path(os.environ.get("GITHUB_WORKSPACE", "./"))
    github_action_path = os.environ.get("GITHUB_ACTION_PATH")
    if not github_action_path:
        github_action_path = github_workspace
    else:
        github_action_path = Path(github_action_path)

    sigma_rules_path = os.environ.get("SIGMA_RULES_PATH")

    # If SIGMA_RULES_PATH is not set, use GITHUB_WORKSPACE as a fallback
    if not sigma_rules_path:
        sigma_rules_path = [github_workspace]
    else:
        # Split the SIGMA_RULES_PATH by newlines and remove empty strings
        sigma_rules_path = [
            github_workspace / Path(path.strip())
            for path in sigma_rules_path.splitlines(True)
            if path
        ]

    # If SIGMA_SCHEMA_FILE is not set, use SIGMA_SCHEMA_URL as a fallback to
    # download the schema file from sigma-specification repository
    sigma_schema_file = os.environ.get("SIGMA_SCHEMA_FILE")
    sigma_schema_url = os.environ.get(
        "SIGMA_SCHEMA_URL",
        "https://raw.githubusercontent.com/SigmaHQ/sigma-specification/main/sigma-schema.json",
    )

    return {
        "GITHUB_WORKSPACE": github_workspace,
        "GITHUB_ACTION_PATH": github_action_path,
        "SIGMA_RULES_PATH": sigma_rules_path,
        "SIGMA_SCHEMA_FILE": sigma_schema_file,
        "SIGMA_SCHEMA_URL": sigma_schema_url,
    }


def generate_all_files(
    root: Path,
    extensions: List[str] = [".yml"],  # TODO: Add support for multiple extensions
    excludes: List[str] = list(),  # TODO: Add support for excludes
) -> Iterator[Path]:
    """Generates all files with the given extensions in the given root directory.

    Args:
        root (Path): Root directory to start the search.
        extensions (List[str], optional): Extensions to search for. Defaults to [".yml"].

    Yields:
        Iterator[Path]: Yields all files with the given extensions in the given root directory.
    """

    for path in root.rglob("*"):
        # NOTE: path.is_file() is used to skip directories, however it will also
        # skip symlinks to files and these symlinked files might reside in inaccessible
        # directories, hence it'll raise a PermissionError. This is why it is run
        # using sudo in the action.yml file. If running as sudo is not an option,
        # the code can be modified to catch the PermissionError and skip the file.
        try:
            if not path.is_file() or any([path.match(ex) for ex in excludes]):
                continue
        except PermissionError:
            warnings.warn(f"PermissionError: Could not access {path}, skipping file")
            continue

        if path.suffix in extensions:
            yield path


def get_rules(sigma_rules_path: List[Path]) -> List[str] | NoReturn:
    """Get all rules from the given paths.

    Args:
        sigma_rules_path (List[Path]): List of paths to search for rules.

    Returns:
        List[str] | NoReturn: List of rules or exit the script if no rules are found.
    """

    rules = list()
    for path in sigma_rules_path:
        for file in generate_all_files(Path(path)):
            rules.append(str(file.resolve().absolute()))

    if len(rules) == 0:
        warnings.warn("No rules found, skipping validation")
        os._exit(-1)

    return rules


def download_schema_file(envs: Dict[str, Any]) -> Path | NoReturn:
    """Download the schema file from the given URL and return its path.

    Args:
        envs (Dict[str, Any]): A dictionary containing the environment variables
            used by the action.

    Returns:
        Path | NoReturn: Path to the schema file or exit the script if
            the file could not be downloaded.
    """

    schema_file = envs["SIGMA_SCHEMA_FILE"]
    schema_url = envs["SIGMA_SCHEMA_URL"]
    if not schema_file:
        schema_file = envs["GITHUB_WORKSPACE"] / "sigma-schema.json"
    else:
        schema_file = Path(schema_file)
        if not schema_file.exists():
            schema_file = envs["GITHUB_WORKSPACE"] / schema_file

    if not schema_file.exists():
        response = requests.get(schema_url)
        if response.status_code == 200:
            with open(schema_file, "wb") as f:
                f.write(response.content)
        else:
            warnings.warn(
                f"Failed to download schema file {schema_file}, skipping validation"
            )
            os._exit(-1)
    return (envs["GITHUB_WORKSPACE"] / schema_file).absolute()


def help() -> None:
    """Prints a help message with the available commands and their descriptions.

    Returns:
        None
    """
    print("Please provide one of the following commands:")
    print("  rules: Get all rules and return them as a string separated by spaces")
    print("  schema: Download schema file and return its path")
    print("  envs: Print all environment variables used by the action")
    print("  help: Print this help message")


if __name__ == "__main__":
    """Main entry point of the script."""

    if len(sys.argv) < 2:
        print("No arguments provided.")
        help()
        os._exit(-1)

    envs = get_envs()
    if sys.argv[1] == "rules":
        print(" ".join(get_rules(envs["SIGMA_RULES_PATH"])))
    elif sys.argv[1] == "schema":
        print(download_schema_file(envs))
    elif sys.argv[1] == "help":
        help()
    elif sys.argv[1] == "envs":
        for key, value in envs.items():
            print(f"{key}: {value}")
    else:
        print(f"Unknown command: {sys.argv[1]}")
        help()
        os._exit(-1)
