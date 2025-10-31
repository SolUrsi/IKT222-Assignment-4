# IKT222-Assignment-4

## How to run project :shipit:

1. To run this project first download the correct Java Development Kit (11.0.18):
    - [JDK](https://cfdownload.adobe.com/pub/adobe/coldfusion/java/java11/java11018/jdk-11.0.18_windows-x64_bin.exe)

2. Now clone the repository:

    ```bash
    git clone https://github.com/SolUrsi/IKT222-Assignment-4.git
    ```

3. Enter the `patients/` directory and run the project:

    ```bash
    ./gradlew run
    ```

4. Enter the `test/` directory to test for sql injections, my own result ouput can be found in results.txt:

    ```bash
    # Create venv
    python -m venv venv

    # Activate venv (Windows)
    .\venv\Scripts\activate

    # Install requirements
    python -m pip install -r requirements.txt

    # Run payload injection test
    python injection.py
    ```

## Finished ✔️
