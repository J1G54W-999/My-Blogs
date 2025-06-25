![Source: www.freepik.com Designed by pikisuperstar](https://media.licdn.com/dms/image/v2/D5612AQFeT6X4wobc5A/article-cover_image-shrink_720_1280/B56ZeKpcw3HUAQ-/0/1750377812855?e=1756339200&v=beta&t=3bkMZl81WIS7kNUgv31wJmGlo_IFGoCzyihilC7TdT4)

# Splunk Threat Hunting - APT DNS Data Exfiltration

![Shae Haseldine, #OPEN_TO_WORK](https://media.licdn.com/dms/image/v2/D5635AQH_FHLn-cQzAA/profile-framedphoto-shrink_100_100/B56Zb9FQLuHcAk-/0/1748002735407?e=1751457600&v=beta&t=0eW_Cl3pEnXK7K2X7tYTN4Dn-DHWdhIbzCWk1Ieap3E)

## Shae Haseldine

BTL1 Certified | Student at CyberLynk

June 20, 2025

Attackers have various ways to access your sensitive data, from password guessing and brute-force attempts, to more elaborate tactics like Phishing emails and watering hole attacks. Once they have access they need to be able to exfiltrate it. One attack that I have recently learnt of is called DNS Tunneling, which is done through a tactic called DNS Data Exfiltration. I learnt about this while doing the Threat Hunting Workshops from Splunk BOTS (Boss of the SOC). Learn with me as I walk you through my investigation.

### What is DNS Data Exfiltration?

This is a method attackers use to send DNS queries from a compromised machine to an external server, which they control. To stay under the radar, the stolen data is broken down into chunks, which is then embedded into the DNS queries within the sub-domain field (usually encoded in something like base64 for obscurity). The DNS query is then sent to the attacker's server and once it arrives, the attacker reconstructs the data from the queries into its original state. Think of it like stealing a car without actually opening the garage door. You take the car apart and walk each part out piece-by-piece and then reassemble it back into a car at a different location. Not the quickest or most efficient, but definitely more stealthy.

![Article content](https://media.licdn.com/dms/image/v2/D5612AQHhJSmz2PM3eA/article-inline_image-shrink_1500_2232/B56ZeL8j1JHUAU-/0/1750399598403?e=1756339200&v=beta&t=GVSphD8QGMHn6WaU4ofQTgS1vhKQS_CK7NsNnkueAmg)

This type of attack is especially harmful as DNS queries are (for the most part) allowed through firewalls as they are essential for resolving domain names to IP addresses so that systems can access websites and when encoded can also get through undetected. Let me show you what this looks like on the Splunk platform.

### The Investigation:

Let's have a look at the Splunk BOTS (Boss of the SOC) platform and I'll walk you through my investigation (DNS Exfiltration) where we conduct a hunt for a company called Frothly and the Taedonggang APT (both fictional).

![Article content](https://media.licdn.com/dms/image/v2/D4E12AQHGs9OrKBBqNg/article-inline_image-shrink_1000_1488/B4EZeLUVNEGwAU-/0/1750389053262?e=1756339200&v=beta&t=BPIrvS_qD5yeikzyzBqqnjuCqhje6lMr8q8mcXuq3FQ)

The specific TTPs we are hunting for can be found on the  [MITRE ATT&CK](https://attack.mitre.org/techniques/T1048/003/)  framework as  **T1048.003: Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol.**  As this data is unencrypted by default, the DNS queries being sent might be a good place to start as these can stand out from all the 'noise' within the logs.

The info we are given to assist out hunt is that a known APT has targeted other organisations similar to our client around August 2017 and sources have identified the IP address 160.153[.]91.7 being used during exfiltration.

So the first search I did was quite simple to just check the DNS stream to show all of the DNS-related traffic and then refine it from there:

_index="botsv2" sourcetype=stream:dns 160.153.91.7_

Scrolling through the interesting fields we have a large amount of volume being referenced to  _hildegardsfarm[.]com_

![Article content](https://media.licdn.com/dms/image/v2/D4E12AQHcQX4FFbv6nQ/article-inline_image-shrink_1000_1488/B4EZeLdJS0HgAc-/0/1750391363350?e=1756339200&v=beta&t=OsRFVbW4r01y3eJM1wd4C_RFfmFZcRDmPvk8gDGtDR0)

It was also referenced by 4 internal systems, so this name was worth investigating.

![Article content](https://media.licdn.com/dms/image/v2/D4E12AQGfvPXaJKLAHg/article-inline_image-shrink_1500_2232/B4EZeLfMeTHIAU-/0/1750391900788?e=1756339200&v=beta&t=OiNuoz7HbNG7Qo7xnguXrpVUldYcLzDFHSkIshGvD_o)

I change my search to look for the name referenced and also added a DNS message type search set to  _QUERY_, as data exfiltration would be coming from an internal machine and making a query out to an external address.

I also want to cut back on the noise, so I used the  _table_ command to search only the time, query, source and destination (much easier to read too).

_index="botsv2" sourcetype=stream:dns hildegardsfarm[.]com message_type=QUERY | table _time query src dest_

![Article content](https://media.licdn.com/dms/image/v2/D4E12AQH1PnL34mtXKA/article-inline_image-shrink_1500_2232/B4EZeLu9d8GcAU-/0/1750396033784?e=1756339200&v=beta&t=Fmu30691OUppQ1AToid5bxkR5IyvrIHizRoHT2T6bLM)

This now shows (quite obviously) some suspicious looking sub-domains related to  _hildegardsfarm[.]com_  which, as mentioned earlier, is how data is broken down into chunks and then exfiltrated piece-by-piece.

So for example, our first result is:  _EYIAAFhTJ2yQaCri.hildegardsfarm[.]com_

The  _EYIAAFhTJ2yQaCri_  should be a sub-domain name, but is actually a piece of the stolen data. Then we have  _hildegardsfarm_ which is the second-level domain (SLD). Finally  _com_, which is the top-level domain (TLD).  So you can see why every request made is almost the exact same, apart from the sub-domain. Suspicious, but also something that has the potential to make it past a firewall undetected.

![Article content](https://media.licdn.com/dms/image/v2/D4E12AQGpP8YynDpICw/article-inline_image-shrink_1000_1488/B4EZeLsiT9HcAU-/0/1750395398321?e=1756339200&v=beta&t=peiUDapYvg0k5ePL4VfJmVH5yFA8wydBsP88JWQLbFU)

Another way to support the theory of DNS exfiltration is the packet size of the requests. If they are all the same size (usually close to the maximum character length) and are systematically recurring, then it would be highly likely that this is the case.

However, one limitation to DNS exfiltration in this way is that there is a limit to DNS packets, so basically if they are too large then they will (or should) be blocked by the firewall. This is why requests are broken down into chunks in the first place.

### Conclusion:

From here you could go on to investigate the domain, check IP addresses and look at ASN's, but I just wanted to show you how this type of attack can be detected and hopefully you found it interesting. I didn't know this was even possible, but anything is when it comes to cybercrime.

Thanks to my mentors at  [CyberLynk](https://www.linkedin.com/company/cyberlynks-pty-ltd/)  for giving me a clear path on my cyber journey and providing the tools I need to succeed and learn. Also, If you are looking to get better at Threat Hunting or just want to play around with Splunk for some experience, then check out the  [Splunk BOTS](https://bots.splunk.com/)  platform. You will learn a lot just doing a few of the hunts!
