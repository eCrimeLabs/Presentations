# Sandstorm

"The answer problem is not in the box, it’s in the band ." – AntiTrust
Although the malware sandboxes have been demonstrated attacked in several ways, this paper will show new attack concept/scenario named “SandStorm”.

The first generation of Sandbox technologies for analyzing malware was a very strict and run in closed environment, where the actual malware execution often was done on emulated OS and services rather than on real systems.

The threats have evolved over the years and malware is becoming more and more dependent on internet access to communicate with a C&C server either to download additional components or configurations, and without this information the analyst will be missing a big piece of the puzzle. The sandbox technology has evolved to cope with the new malware threats.

Over a period of 2 month various tests was made to see if the concept was pure theoretical or could be used in real world attacks, as will be shown in this paper.

This paper will have primary focus on binary analysis systems, however the attack sources are much wider, and a solution will come with a price.
None of the systems used in this test will be named they are all numbered.

Even if this is an research paper of mine back from 2012 my guess is that this is still a threat towards many sandbox systems.

As a side finding it was observed that the security vendors in some cases added the domains being attacked to block lists as being malicious.