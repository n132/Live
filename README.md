# Live
Script for Live CTF

# ls
List all the challenges
```shell
./Live ls
```

# get

Get the challenge attachment and decompress it.
```shell
./Live get <challengeId>
```

# solve

Test the local solution at `./challenge/handout/exp.py`

```shell
./Live solve
```

# submit

Compress a solve tarball with script at  `./challenge/handout/exp.py` and submit it.

```shell
./Live submit <challengeId>
```

# exp

Check the submitted solution state.

```shell
./Live exp <exploitation_tag>
```
