# cryptopals-solutions

Solutions in Rust to the exercises from http://cryptopals.com/

File `inputs/corpus.txt` was retrieved from the [Leipzig Corpora Collection
Download Page](http://corpora2.informatik.uni-leipzig.de/download.html)
(specifically the "2010-wiki-100K" dataset, language "eng", format "Plain Text
Files"), where it is available under the [CC BY
license](https://creativecommons.org/licenses/by/4.0/). It was then reduced in
size by removing all but the first 1,000 lines.

## Usage

By default, all challenges are run. You can change this by specifying the
desired challenges on the command-line.

E.g.:

```
$ cargo run --release -3 5 7-9 11-
```

will run challenges 1, 2, 3, 5, 7, 8, 9, 11 and all subsequent ones.
