

Password cracker. Can also generate custom wordlists & apply rule permutations.  
**Speed is limited to the power of the CPUs dedicated to the task.  
  
Config file: /etc/john/john.conf  
  
To mutate a wordlist, navigate to **[List.Rules:Wordlist]** segment, add section for your own rules ( [List.Rules:myrules])  
  
  
Create hash file from .zip or .rar:  
```bash
zip2john flag.zip  
rar2john flag.rar
```


Usage:  
```bash
john [ OPTIONS ] [ PASSWORD-FILES ]
```


Brute forcing:  
	Supply pw file (& hopefully format).  
	Can take a long time  
  
Wordlist:  
	**--wordlist**  
	Faster, but less coverage.  
  
Word mangling:  
	**--rules**  
	Recommend if any pw left after BF & Wordlist are exhausted.  
  
  
Linux:  
	Need to combine _/etc/passwd_ & _/etc/shadow_ fies w/ **unshadow**  
```bash
unshadow passwd-file.txt shadow-file.txt > unshadowed.txt
```

 
**--fork** & **--node** ex:  
	Assuming two machines, each with an 8-core CPU.  
		1st machine - **--fork=8** & **--node=1-8/16**:  
			Creates eight processes on this machine  
			Splits the supplied wordlist into sixteen equal parts  
			Process the first eight parts locally.  
		2nd machine - **--fork=8** & **--node=9-16**:  
			Assigns eight processes to the 2nd half of the wordlist.  
  
  
  
  
--help     Print usage summary  
--single\[=SECTION\[,..\]\]         "Single crack" mode, using default or named rules  
--single=:rule\[,..\]                         Same, using "immediate" rule(s)  
--single-seed=WORD\[,WORD\]     Add static seed word(s) for all salts in single mode  
--single-wordlist=FILE         *Short* wordlist with static seed words/morphemes  
--single-user-seed=FILE     Wordlist with seeds per username (user:password\[s\] format)  
--single-pair-max=N             Override max. number of word pairs generated (6)  
--no-single-pair                     Disable single word pair generation  
--\[no-\]single-retest-guess         Override config for SingleRetestGuess  
--wordlist\[=FILE\] --stdin             Wordlist mode, read words from FILE or stdin  
                    --pipe                        like --stdin, but bulk reads, and allows rules  
  
--rules\[=SECTION\[,..\]\]         Enable word mangling rules (for wordlist or PRINCE modes), using default or named rules  
--rules=:rule\[;..\]\]                 Same, using "immediate" rule(s)  
--rules-stack=SECTION\[,..\]             Stacked rules, applied after regular rules or to modes that otherwise don't support rules  
--rules-stack=:rule\[;..\]             Same, using "immediate" rule(s)  
--rules-skip-nop                         Skip any NOP ":" rules (you already ran w/o rules)  
  
--loopback\[=FILE\]                 Like --wordlist, but extract words from a .pot file  
--mem-file-size=SIZE             Size threshold for wordlist preload (default 2048 MB)  
--dupe-suppression                 Suppress all dupes in wordlist (and force preload)  
--incremental\[=MODE\]             "Incremental" mode \[using section MODE\]  
--incremental-charcount=N             Override CharCount for incremental mode  
--external=MODE                 External mode or word filter  
--mask\[=MASK\]                     Mask mode using MASK (or default from john.conf)  
--markov\[=OPTIONS\]             "Markov" mode (see doc/MARKOV)  
--mkv-stats=FILE                 "Markov" stats file  
  
--prince\[=FILE\]                 PRINCE mode, read words from FILE  
--prince-loopback\[=FILE\]             Fetch words from a .pot file  
--prince-elem-cnt-min=N             Minimum number of elements per chain (1)  
--prince-elem-cnt-max=\[-\]N             Maximum number of elements per chain (negative N is relative to word length) (8)  
--prince-skip=N                 Initial skip  
--prince-limit=N                 Limit number of candidates generated  
--prince-wl-dist-len                 Calculate length distribution from wordlist  
--prince-wl-max=N                 Load only N words from input wordlist  
--prince-case-permute                 Permute case of first letter  
--prince-mmap                 Memory-map infile (not available with case permute)  
--prince-keyspace                 Just show total keyspace that would be produced (disregarding skip and limit)  
  
--subsets\[=CHARSET\]                 "Subsets" mode (see doc/SUBSETS)  
--subsets-required=N                 The N first characters of "subsets" charset are The "required set"  
--subsets-min-diff=N                 Minimum unique characters in subset  
--subsets-max-diff=\[-\]N                 Maximum unique characters in subset (negative N is relative to word length)  
--subsets-prefer-short                 Prefer shorter candidates over smaller subsets  
--subsets-prefer-small                 Prefer smaller subsets over shorter candidates  
  
--make-charset=FILE                 Make a charset, FILE will be overwritten  
--stdout\[=LENGTH\]                 Just output candidate passwords \[cut at LENGTH\]  
--session=NAME                 Give a new session the NAME  
--status\[=NAME\]                 Print status of a session \[called NAME\]  
--restore\[=NAME\]                 Restore an interrupted session \[called NAME\]  
--\[no-\]crack-status                 Emit a status line whenever a password is cracked  
--progress-every=N                 Emit a status line every N seconds  
  
--show\[=left\]                 Show cracked passwords \[if =left, then uncracked\]  
--show=formats                 Show information about hashes in a file (JSON)  
--show=invalid             Show lines that are not valid for selected format(s)  
--test\[=TIME\]                 Run tests and benchmarks for TIME seconds each (if TIME is explicitly 0, test w/o benchmark)  
--stress-test\[=TIME\]                 Loop self tests forever  
--test-full=LEVEL                 Run more thorough self-tests  
  
--no-mask             Used with --test for alternate benchmark w/o mask  
--skip-self-tests             Skip self tests  
--users=\[-\]LOGIN|UID\[,..\] \[Do not\]            load this (these) user(s) only  
--groups=\[-\]GID\[,..\]             Load users \[not\] of this (these) group(s) only  
--shells=\[-\]SHELL\[,..\]             Load users with\[out\] this (these) shell(s) only  
  
--salts=\[-\]COUNT\[:MAX\]             Load salts with\[out\] COUNT \[to MAX\] hashes, or  
--salts=#M\[-N\]             Load M \[to N\] most populated salts  
--costs=\[-]\C\[:M\]\[,...\]             Load salts with\[out\] cost value Cn\[to Mn\]. For tunable cost parameters, see doc/OPTIONS  
--fork=N         Fork N processes  
--node=MIN\[-MAX\]/TOTAL             This node's number range out of TOTAL count**  
  
--save-memory=LEVEL                 Enable memory saving, at LEVEL 1..3  
--log-stderr                 Log to screen instead of file  
--verbosity=N                 Change verbosity (1-5 or 6 for debug, default 3)  
--no-log                 Disables creation and writing to john.log file  
--bare-always-valid=Y             Treat bare hashes as valid (Y/N)  
  
--catch-up=NAME             Catch up with existing (paused) session NAME  
--config=FILE                 Use FILE instead of john.conf or john.ini  
--encoding=NAME                 Input encoding (eg. UTF-8, ISO-8859-1). See also doc/ENCODINGS.  
--input-encoding=NAME                 Input encoding (alias for --encoding)  
--internal-codepage=NAME                 Codepage used in rules/masks (see doc/ENCODINGS)  
--target-encoding=NAME             Output encoding (used by format)  
  
--force-tty             Set up terminal for reading keystrokes even if we're not the foreground process  
--field-separator-char=C             Use 'C' instead of the ':' in input and pot files  
--\[no-\]keep-guessing             Try finding plaintext collisions  
--list=WHAT             List capabilities, see --list=help or doc/OPTIONS  
  
--length=N             Shortcut for --min-len=N --max-len=N  
--min-length=N             Request a minimum candidate length in bytes  
--max-length=N             Request a maximum candidate length in bytes  
--max-candidates=\[-\]N             Gracefully exit after this many candidates tried. (if negative, reset count on each crack)  
--max-run-time=\[-\]N             Gracefully exit after this many seconds (if negative, reset timer on each crack)  
  
--mkpc=N             Request a lower max. keys per crypt  
--no-loader-dupecheck             Disable the dupe checking when loading hashes  
--pot=NAME             Pot file to use  
--regen-lost-salts=N             Brute force unknown salts (see doc/OPTIONS)  
--reject-printable             Reject printable binaries  
--tune=HOW             Tuning options (auto/report/N)  
--subformat=FORMAT             Pick a benchmark format for --format=crypt  
--format=\[NAME|CLASS\]\[,..\]             Force hash of type NAME. The supported formats can be seen with --list=formats and --list=subformats.  
  

See also doc/OPTIONS for more advanced selection of format(s), including using classes and wildcards.