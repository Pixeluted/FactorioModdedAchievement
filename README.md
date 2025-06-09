## Factorio Modded Achievement

This tweak enables you to get achievements within Steam even while you have mods active. It is targeted at people who use vanilla+ mods (which is my case and why I created this).

Some of you know that this has been done before, but the previous project is now completely broken and doesn't work. Plus, it relied on AOB scans which can easily break between updates.

### Technical Explanation 
(You can skip this if you just want to install it)

This tweak works by DLL proxying the steam_api64.dll that the game needs. This loads our DLL which then parses the game's PDB and locates the necessary addresses and offsets to enable achievements.

This approach is much more reliable because as long as Wube Software provides a PDB for Factorio, the tweak will continue to work even if they change their code. While it could still break and require updates, this is much less likely than with the previous enabler.

### Addressing Security Concerns

I want to address potential concerns that this might be a virus or could become one in the future. I completely understand your hesitation to trust an unknown developer.
To help with your decision about installing this tweak:
  1. The DLL is completely open source and unobfuscated, meaning anyone can review or reverse engineer the code if they want extra assurance.
  2. Regarding future updates, I can promise I'll never insert malicious code, but I recognize that's just my word. Ultimately, it's up to you whether to trust a random person on GitHub and the Factorio forum.

### Installation
[![Installation Video](https://img.youtube.com/vi/nOKb47lJKlE/0.jpg)](https://www.youtube.com/watch?v=nOKb47lJKlE)
