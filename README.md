# Corgea CLI
Corgea one-line command to upload SAST results. This command will run your scanner, and send the vulnerabilities report to Corgea for analysis.


<Card>

[Watch video](https://www.loom.com/share/0d3ed94d1f01401a86906fc9713ee709?sid=b11c1f5a-66ff-4dbf-a83a-c9bea15a5d7b)

[![](https://cdn.loom.com/sessions/thumbnails/0d3ed94d1f01401a86906fc9713ee709-with-play.gif)](https://www.loom.com/share/0d3ed94d1f01401a86906fc9713ee709?sid=b11c1f5a-66ff-4dbf-a83a-c9bea15a5d7b)

</Card>

## Installation

### Using pip
```
pip install corgea-cli
```

### Manual Installation
You can get the latest binaries for your OS from https://github.com/Corgea/cli/releases.

### Setup
Once the binary is installed, login with your token from the Corgea app.
```
corgea login <token>
```


## Development Setup

### Prerequisites
- Python 3.8 or higher
- Rust toolchain (for maturin)

### Using venv (Python Virtual Environment)
1. Create and activate a virtual environment:
   **** 
   python -m venv .venv
   source .venv/bin/activate  # On Unix/macOS
   .venv\Scripts\activate     # On Windows
   ****

2. Install dependencies:
   ****
   pip install -r requirements.txt
   ****

3. Build and install the package in development mode:
   ****
   maturin develop
   ****

### Using Conda
1. Create and activate a conda environment:
   ****
   conda create -n corgea-cli python=3.8
   conda activate corgea-cli
   ****

2. Install dependencies:
   ****
   pip install -r requirements.txt
   ****

3. Build and install the package in development mode:
   ****
   maturin develop
   ****

Note: After making changes to Rust code, you'll need to run `maturin develop` again to rebuild the package.

