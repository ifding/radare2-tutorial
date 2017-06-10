
# An Introduction to radare2

Radare2 (also known as r2) is a complete framework for reverse engineering and analyzing binaries; composed of a set of small utilities that can be used together or indendently from the command line. Other reverse engineering tools include [IDA](https://www.hex-rays.com/products/ida/) and [Hopper](http://www.hopperapp.com/).

Official repository of radare2 is [here](https://github.com/radare/radare2). On Mac OSX, `brew install radare2` will do the job. For other OS, check out the installation page on radare.org.

A full(?) feature list of r2 and comparison of r2 vs Hopper vs IDA can be found [here](http://rada.re/r/cmp.html)

If everything goes well, you'll find multiple tools in your path:

- r2 – the "main" binary
- rabin2 – binary to analyze files (list imports, exports, strings, …)
- rax2 – binary to convert between data formats
- radiff2 – binary to do some diffing
- rahash2 – creates hashes from file blocks (and whole file)
- rasm2 – helps to play with assembler instructions

## Introduction

**Links to other cheatsheets and documentations (which you may like):** 

  * [Cheat sheet](https://github.com/radare/radare2/blob/master/doc/intro.md)
  * [Official Radare2 Book](http://maijin.gitbooks.io/radare2book/content/)
  * [Using radare2 for Pwning](http://radare.today/using-radare2/)
  * [radare2 blog](http://radare.today/) has some interesting articles to pwn ctf challenges using r2.
  * [radare2 Wiki](https://github.com/radare/radare2/wiki)
  * \#radare (official channel) on irc.freenode.net if you need any help from r2 folks anytime.

r2 has a ton of features which takes a lot of time to explore and understand. Think of r2 like vim/emacs. Unfortunately it lacks a robust GUI. Feel free to try out the web GUI or [Bokken](https://inguma.eu/projects/bokken)

It has a steep learning curve but we need only a few commands to do basic reversing (and for ctfs) and that is all we'll be seeing for today :)


## A (very) small tutorial for absolute newbies:

Radare uses a tree structure like name of the commands so all commands which corresponds to analyzing someth
ing start with a. If you want to print something you have to use... p. For example disassemble the current f
unction: pdf [print disassembly function].

**Most Important tip for today (and as long as you use r2!):** What most people don't realise is that r2 is self-documenting. Whenever you don't know any command, its semantics, what it does etc. use `?`. A single ? shows you which command categories are available and some general help about specifying addresses and data.

**Example:** Just running `?` will give you a list of all commands.
Now look at `a`. The help menu says: *"Perform analysis of code"*.
To get more information about commands starting from `a`, run `a?`.
Use this to learn and discover r2. When in doubt feel free to consult wikis, guides and talk to people on \#radare. `q` is usually used to exit menus and eventually radare2 itself.

A `p?` shows you the help about the different print commands, `pd?` which commands are available for printing disassemblies of different sources, etc.

Also usually all mneumonics are dervied from their longer form.

Usually this is the workflow you would follow:

- Start up r2 by using: `$ r2 ./hello_world`
- Run `aa` to "Analyze All", or the newer `aaa`.
- Enter `V` to enter "Visual Mode". (**Hint**: You can use `?` in Visual mode too)

- To view the graph of a function hit `V`. If you don't see a graph when you enter into graph mode, it usually means that you forgot to run the analysis (rarely it could be a bug in r2, in which case please do report).

- Hit `p` to show the disassembly at the current location. Hit `p` again to go into debugger mode which shows all register states.

- `v` to enter code analysis menu. This menu shows all the functions analysed. Selecting one and pressing `g` "seeks" to that function. So the first thing to do is seek to the main function. This will usually be shown as 'main' or 'sym.main'. Normally you'll want to begin analysing the binary from here.

- In visual mode, if you want to run a r2 command, simple hit `:`. This brings up the same shell that you would have access to outside of the visual mode. All commands that work there work here too. To close the command line, just hit enter with a blank line.

- use `s <fn_name>` (**Example:** `s sym.main` will take you to main directly) or `s <offset> ` to "seek" to locations. `s-` to undo seek, and `s+` to redo seek. This allows you to traverse the binary efficiently. Tab completion is available to help you out here :)

- After some analysis, you might want to rename functions, to do so use `afn <new_name> [offset]`.

- To rename **local variables**, use `afvn [identifier] [new_name]`. This is the same for **function arguments**, but use `afan` instead.

- Once you have done some analysis, you will want to save your work so that you can return to it later, use `Ps [name]` to save it as a project. Please check out `P?` for other project related commands. Most of them are self-explanatory.

- To load a project, use `Po [name]`. Alternatively, you could also do this while starting up r2 buy using the -P option. (**Example:** `$ r2 -P [name]`)

- If you're a little afraid of this huge amount of command line, you could also try the web interface: `r2 -c=H your_binary`.

### Additional:

- To show all strings in a the data section of a binary, try: `iz`.
- To show all strings in the entire binary try: `izz`.
- Want to search for a string 'Foo' in the binary? Simple, do: `/ Foo`.
 - This will return something like: `> <offset> hit0_X "Foo"`. To quickly go to this location, `s hit0_X`. Again, tab-completion is available.
- To help further with traversal, r2 offers vim style marks. To place a mark at an offset, use `mK`. Jump to a mark 'K' by using `'K` (exactly how it works in vim!).
- Don't like a theme? Check out default themes using `eco?`. To select a theme run `eco [name] `.

### TODO

- `o` to seek.
- `u/U` to undo/redo seek.
- `dr` and `d` in general in visual mode.

## Reference

- [An Introduction to radare2](http://sushant94.me/2015/05/31/Introduction_to_radare2/)
- [Reverse Engineering With Radare2 – Intro](https://insinuator.net/2016/08/reverse-engineering-with-radare2-intro/)
