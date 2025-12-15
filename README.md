## Threat-Detected
# Scenario
Angela Ingram called in on January 10th around 4 PM UTC mentioning that her computer had a pop-up saying something about threat detected. 
She does not recall clicking on anything and her computer is working fine, but wanted to report this just in case.

#Objective
Finding out what happened creating an investigation report containing findings, investigations, 5Ws & 1H along with recommendation and a timeline of events

# Steps
Angela mentioned something about threat detected and she called in around 4PM. Narrow the search time to 3 PM to 5 PM on January 10th, 
as this will provide us with 1 hour of activity both before and after Angela called.
<img width="1071" height="366" alt="Screenshot 2025-12-15 164857" src="https://github.com/user-attachments/assets/5e31fff1-b656-4087-a30a-04dfd22c6f92" />
- Theres over 10k events which is a bit hard to work with. Narrow this by including Angela's computer, we can achieve this by using her username from
  the user field
  <img width="987" height="562" alt="image" src="https://github.com/user-attachments/assets/84249024-02b6-4ceb-9ccf-5825437b07cc" />
- Then to find her computer, filter for her username account by selecting aingram. This will narrow the search to filter specifically for Angela's account;
 <img width="1052" height="584" alt="image" src="https://github.com/user-attachments/assets/f083913e-56d1-484e-b96f-5b3d5496b1f6" />
- The events now drops to 464 events which is a bit better. In this field we have two values one being domain controller which is normal in a domain-joined environment
 that has Active Directory,because it uses Kerberos for authentication.
- Add the Angela's computer to our search:
  <img width="1078" height="563" alt="image" src="https://github.com/user-attachments/assets/d64746f3-b1c5-476c-849e-479d0ca52d42" />
- This gives 401 events.
- Threat detection is normally triggered by technologies such as antivirus, EDR or IPS/IDS, looking at the source field theres only WinEventLog:Security
  <img width="1077" height="655" alt="image" src="https://github.com/user-attachments/assets/784637d8-b14a-4ccb-8a67-70947c73121f" />
- We can broaden the search a little bit by removing Angela's username and focusing on her computer instead. The user mentioned she saw the threat detected on her computer.
<img width="1079" height="715" alt="image" src="https://github.com/user-attachments/assets/235d8888-80ff-4b5c-94d0-8f8888d2058c" />
- Reviewing the logs we now have 5 sources. We can see Windows Defender which relates to the technologies we are looking for:
 <img width="992" height="413" alt="image" src="https://github.com/user-attachments/assets/7c8bf3c7-16dd-478c-8915-c84f15f82a0e" />
- Adding to our search generates 24 events which more manageable:
  <img width="1083" height="564" alt="image" src="https://github.com/user-attachments/assets/261644fb-4c21-4021-ba27-e06599c6ca45" />

  
- Lookin at our earliest event was at 4:08:11.000 PM wuth a message field reading "Microsoft Defender Antivirus has detected malware or other potentially unwanted software"
<img width="790" height="661" alt="image" src="https://github.com/user-attachments/assets/fa45c9ef-13dd-4794-b6c0-3a81d36ac4f5" />
- Taking note of the name RemoteExec, the random characters and user system this doesnt look good. Attackers love to abuse the System account as it has full
   permissions to do whatever it wants to the computer. However theres a lot of legimate System usage, but the system running this strange file makes it suspicous.
- Looking up on Win32/RemoteExec: 
  <img width="694" height="416" alt="image" src="https://github.com/user-attachments/assets/f674ca8e-93d5-4c49-839e-242357bd2f1f" />
- Expanding on this event we can see EventCode 1116 for Windows Defender. This Event Code triggers if Defender detects malware or other potential unwanted software.
  <img width="659" height="321" alt="image" src="https://github.com/user-attachments/assets/0080764d-b714-4f2d-b4ad-7f3d8636cdc6" />
- Next we can scope the environment using the Event Code 1116 to look for other potential computers that Defender might have detected malware on:
  <img width="1079" height="780" alt="image" src="https://github.com/user-attachments/assets/26c62b86-7953-43ee-84bc-1c0cb60b4cdf" />
  and we have only 9 events all sourcing from Angela's computer.
# Chain of events
- Looking at the next event that happened at 4:08:40.000 PM we a message field of "Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software". 
  <img width="795" height="719" alt="image" src="https://github.com/user-attachments/assets/5ab1e517-97cf-4672-93cc-c9c64c7216b3" />
- The Action Status of "No additional actions required", DOES THIS MEANS WE SHOULD STOP FROM HERE? DEFINITELY NOT. We must investigate how this malware got onto this computer.

- Following the chain of events by looking at more detections from Defender at 4:10:29.000 PM the was a different file and Defender blocked it
  <img width="807" height="657" alt="image" src="https://github.com/user-attachments/assets/54b2e8c2-2e84-4f59-8786-e055577dfa4a" />
- At 4:11:39.000 PM Event Code 50017 shows Defender was disabled, this could be the malware or user disabling it;
    <img width="788" height="396" alt="image" src="https://github.com/user-attachments/assets/0d201fe6-8e9e-40ef-b96f-dd29335c0f76" />
- Now we can confidently say Defender detected and blocked malware and it was disabled. Next is to find what else happened.
- At  4:12:17.000 PM with Event Code 5000 shows Defender was enabled;
  <img width="789" height="391" alt="image" src="https://github.com/user-attachments/assets/6ef87218-d17e-4473-850c-10c3cb193ad5" />

- At 4:38:31.000 PM we see an exculsion was made to the file path \c:\Windows\Temp. This rise the question why a temporary directory is being excluded?
Perphaps an attacker is going to upload a malware?
  
<img width="805" height="459" alt="image" src="https://github.com/user-attachments/assets/8bb7380f-9b55-4898-8994-4c2f25adf9e2" />

- 4:15:55.000 PM shows a process also being excluded
<img width="767" height="452" alt="image" src="https://github.com/user-attachments/assets/96c14b46-d302-4b69-b0e8-86ad97ce3d3a" />

# Defender Logs
By following the chain of events we know:
- Theres a potential starting time 16:08:11 and the potential end time 16:38:31
- A remote shell was trying to be established based on the signature
- C:\Windows\Temp was added to the exclusion list.

# Analysis
Windows Temp being exclude creates a baseline for this investigation. 
- Going back to the event that occured at 1/10/24 16:15:53.000 PM and look at +/-5 minutes from this activity removing the Defender Source.
<img width="1075" height="466" alt="image" src="https://github.com/user-attachments/assets/8b67735f-d030-4389-9d96-9549a2305e09" />

- This generates 325 events which is still quite a bit of data. We can narrow by including the "temp". Which generate 10 events.
<img width="1070" height="746" alt="image" src="https://github.com/user-attachments/assets/688b51c6-142b-4cd5-9fe9-3c13c93ec262" />
