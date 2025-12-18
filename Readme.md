# Secure File Vault

## How to install

```bash
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes --only-binary=all -r requirements.txt
# To install tests dependencies
pip install --require-hashes --only-binary=all -r requirements_test.txt
```

## How to run

```bash
# To run with the TUI (Terminal User Interface)
python src/main.py
# To see usage
python src/main.py --help
# To run test
pytest
```

## For more information
Please refer to the documentation in the `docs` folder.
Link to the docs: [View the documentation](./docs/documentation.md)
Link to the implementation plan: [View the implementation plan](./docs/implementation-plan.md)
