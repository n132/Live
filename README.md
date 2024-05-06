# Live
Script for Live CTF

- Make sure you print the flag in stdout
- If the submitted tarball keeps running, check the permission issue of `submit.tar` or try to submit manually
- For exploits load `libcs`, copy the libc to `challenge/exploit` and modify `challenge/exploit/Dockerfile` with adding `COPY libc.so.6 libc.so.6`

# Commands
## ls
List all the challenges
```shell
./Live ls
```

## get

Get the challenge attachment and decompress it.
```shell
./Live get <challengeId>
```

## solve

Test the local solution at `./challenge/handout/exp.py`

```shell
./Live solve
```

## submit

Compress a solve tarball with script at  `./challenge/handout/exp.py` and submit it.

```shell
./Live submit <challengeId>
```

## exp

Check the submitted solution state.

```shell
./Live exp <exploitation_tag>
```
