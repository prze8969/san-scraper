.PHONY: all build test samples run clean

all: build test

build:
	python -c "import compileall; compileall.compile_dir('src', force=True, quiet=1); compileall.compile_dir('tools', force=True, quiet=1); compileall.compile_dir('tests', force=True, quiet=1)"

test:
	python -m unittest discover -s tests -v

samples:
	python tools/generate_samples.py sample_data

run:
	python -m src.cli sample_data output_data

clean:
	python -c "import shutil, pathlib; [shutil.rmtree(p) for p in pathlib.Path('.').rglob('__pycache__')]; [p.unlink() for p in pathlib.Path('.').rglob('*.pyc')]"
