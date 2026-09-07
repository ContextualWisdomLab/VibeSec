### Changed

- Consolidated six exact-coverage workflows into the existing Python 3.13 test job, removing six workflow and runner admissions per pull request while retaining every focused 100% statement-coverage contract.
- Kept each coverage group in a separate Python process so module import state cannot hide unexecuted statements, while sharing checkout, interpreter setup, and hash-locked dependency installation.
