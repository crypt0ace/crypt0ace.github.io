---
title: "Panic At The Disco - Stego Challenge"
date: 2021-06-13
description: "A Stegonography Challenge from DigitalOverdose CTF 2021"
tags: [Write-Ups]
---

Here we are given a simple png file.
\
![PanicAtTheDisco.png](/assets/img/panic-at-the-disco/PandeAtTheDisco.png)
\
So as some of the first checks, I ran string on it
```
strings PandeAtTheDisco.png
```
\
And found what looks like a base64 encoded string:
```
ZmxhZ3thcHBvbHNfYXJlX3Rhc3R5fQ==
```
\
\
So i used the base64 -d command on terminal to decode it and get the flag!
\
![Flag.png](/assets/img/panic-at-the-disco/flag.png)
\
\
And voila! we get the flag!