

## Note Taking

#### Principles
- Rather than taking a few general notes assuming that we'll remember how to perform certain actions next time, we should record exactly what we did.
- This means that every command that we type, every line of code that we modify, and even anywhere we click in the GUI should be recorded so that we can reproduce our actions.
- Even if we've taken a lot of notes, if looking at them later doesn't help us remember exactly what happened during the assessment, then they won't be particularly useful to us.
- The notes need to be structured and sufficiently detailed to remove any ambiguity.
- To write a convincing and substantiated technical report later, we need to provide sufficient technical details within our notes.
- If the notes are not written coherently, it will be difficult for someone else to repeat the test and get the same results.

#### Structure

- **Application Name**: This is important in a multi-application test, and a good habit to get into. The application names also lends itself to building a natural folder and file structure quite nicely.
- **URL**: This is the exact URL that would be used to locate the vulnerability that we've detected.
- **Request Type**: This represents both the type of request (i.e: GET, POST, OPTIONS, etc) that was made, as well as any manual changes we made to it. For example, we might intercept a POST request message and change the username or password before forwarding it on.
- **Issue Detail**: This is the overview of the vulnerability that will be triggered by our actions. For example, we may point to a CVE describing the vulnerability if one exists, and/or explain the impact we observe. We may categorize the impact as denial of service, remote code execution, privilege escalation, and so on.
- **Proof of Concept Payload**: This is a string or code block that will trigger the vulnerability. This is the most important part of the note, as it is what will drive the issue home and allow it to be replicated. It should list all of the necessary preconditions, and provide the exact code or commands that would need to be used to perform the triggers the vulnerability again.

#### Example:

Test run:
![](note_ex_test.png)

Result:
![](note_ex_test2.png)

Notes:
![](note_ex.png)
	These notes are invaluable when compiling the report for the client.


#### Screenshots:

Screenshots should be used to supplement note-taking or to include them in the report to illustrate the steps taken, but be conscious of the audience.
While a penetration tester may consider an alert window to demonstrate XSS as perfectly self-explanatory, developers unfamiliar with the vulnerability may not understand its true cause or impact.
It's good practice to always support a screenshot with text.

They have a specific goal: Convey information that would take several sentences to describe or to make an impact.
With this in mind, the screenshot should contain exactly enough information to justify not using text, but there shouldn't be too much information to make the screenshot confusing.

###### To return to the example above:

The effects of XSS will be properly explained in the actual report, but the impact is far easier to show.
Evidence of arbitrary JavaScript execution must be shown, as well as visual components of the site (i.e. the URL in the browser window).
If necessary, secondary or lead-up steps can be captured as well.

Ideally include the URL & some company-specific branding and logos on the form.  Resize the window if necessary.
This lets them know the exact webpage and ties the vulnerability to their corporate image.

The actual pop-up executed in the POC is necessary, substituted for any more advanced payload as the POC is slowly taken further.
Also ensure there isn't more than one concept illustrated in each screenshot.

A good screenshot:
- is legible
- contains some visual indication that it applies to the client
- contains the material that is being described
- supports the description of the material
- properly frames the material being described

A bad screenshot:
- is illegible
- is generic rather than client-specific
- contains obfuscated or irrelevant information
- is improperly framed

Under the screenshot, include an 8-10 word max caption. A caption is not meant to provide additional context for the picture.
A caption is there to describe the picture in a few words. Any additional context that is necessary can be provided in a separate paragraph.



## Report Writing

The end goal is for the client to be presented with a path forward that outlines and highlights all the flaws that are currently present in their systems within the scope of the engagement, ways to fix those flaws in an immediate sense, and strategic goals that will prevent those vulnerabilities from appearing in the future.

In the case where a vuln isn't found, avoid including too many technical details on what was done in the report.
A simple statement that no vulnerabilities have been found is often sufficient so as not to confuse the client with the technical details of any attempts, as this will undermine the value of the issues actually found.

The client receiving the report is (*should be*) an expert in their own specific industry and may (though not always) be aware of the security concerns of that industry and will expect us to have done our homework to also be aware of them.  In practice, this means having a deep understanding of what would cause concern to the client in the event of an attack.  In other words, understanding their key business goals and objectives. This is another reason why being clear on the Rules of Engagement is so important, because it gives us a window into the client's core concerns

It's important to highlight issues found based of the priority of the client's needs.

##### Tailor the content

**Ex:**
Client A is a hospital.  Client B is a bank.

As Client A is more likely to have life-necessary devices running on obsolete OS/ applications, patching will be near impossible, so recommending the machines be isolated onto their own logical subnet would be best.
However, for Client B, a missing patch would be marked critical as it could be a foothold for a network attack.  Also network segmentation would be unfeasible, so that would certainly not be included in any recommendations.

As report writers, we must present useful, accurate, and actionable information to the client without inserting our own biases.

Furthermore, in tailoring the content, consider the audience: C-suite level execs vs IT/ security staff.


## Report Structure

### Executive Summary

First section of a report enabling senior management to understand the scope and outcomes of the testing at a sufficient level to understand the value of the test, and to approve remediation.

Outlines:
- Scope of the engagement
- Statement of exactly what was tested, and if anything dropped from scope
- Timing issues (e.g. too many vulns found to adequately report on)
- Time frame of the test (length of time, dates, testing hours, etc)
- Summary of Rules of Engagement and include referee notes (if a referee were used).
	- Should include any specific testing methodologies used.
- Supporting infrastructure and accounts
	- Using webapp ex:  User accounts given by client, IP addresses from attack (testing) machines, any accounts created (to ensure proper deletion).

Ex:
![](exec_summary_details.png)

After the outline summation above, a long-form summary is written of the testing providing a high-level overview of each step of the engagement establishing severity, context, and a "worst-case scenario" for the key findings from the testing.
It's important not to undersell or oversell the vulnerabilities.  The client's mental model of their security posture needs to be accurate.

Any trends should be noted and included grouped with similar vulns.
Having XSS, SQLi, and file upload vulns shows that user supplied data is not being properly sanitized across the board and needs to be fixed at a systemic level.

**Don't forget to include things that were done well!**

It's important to point out positive things as well.   Makes the report (esp when finding severe vulns) easier to take.

##### Breakdown

1 -  Include a few sentences describing the engagement:
```
- "The Client hired OffSec to conduct a penetration test of
their kali.org web application in October of 2025. The test was conducted
from a remote IP between the hours of 9 AM and 5 PM, with no users
provided by the Client."
```
	Describing the Engagement

2 - Add several sentences that talk about some effective hardening we observed:
```
- "The application had many forms of hardening in place. First, OffSec was unable to upload malicious files due to the strong filtering
in place. OffSec was also unable to brute force user accounts
because of the robust lockout policy in place. Finally, the strong
password policy made trivial password attacks unlikely to succeed.
This points to a commendable culture of user account protections."
```
	Identifying the positives

Notice the language here:  Don't make absolute claims without absolute evidence.  There's limited time, budget, and fallibility involved.  Just because a vuln couldn't be found doesn't mean it doesn't exist.

3 - Introduce a discussion of the vulnerabilities discovered:
```
- "However, there were still areas of concern within the application.
OffSec was able to inject arbitrary JavaScript into the browser of
an unwitting victim that would then be run in the context of that
victim. In conjuction with the username enumeration on the login
field, there seems to be a trend of unsanitized user input compounded
by verbose error messages being returned to the user. This can lead
to some impactful issues, such as password or session stealing. It is
recommended that all input and error messages that are returned to the
user be sanitized and made generic to prevent this class of issue from
cropping up."
```
	Explaining a vulnerability

Several paragraphs of this type may be required, depending on the number and kind of vulns found. Use as many as necessary to illustrate the trends, but try not to make up trends where they don't exist.

4 - Conclude with an engagement wrap-up:

```
"These vulnerabilities and their remediations are described in more
detail below. Should any questions arise, OffSec is happy
to provide further advice and remediation help."
```
	Concise conclusion


### Testing Env Considerations

First section of the full report should detail any issues that affected the testing.
Usually a small section, but should include any mistakes or extenuating circumstances that occur during an engagement.

Important for transparency and helps to improve on the next iteration of testing and get the most value for the money being paid.

3 Potential 'extenuating circumstances' states:
- **Positive Outcome**: "There were no limitations or extenuating circumstances in the engagement. The time allocated was sufficient to thoroughly test the environment."
    
- **Neutral Outcome**: "There were no credentials allocated to the tester in the first two days of the test.  However, the attack surface was much smaller than anticipated.  Therefore, this did not have an impact on the overall test.  OffSec recommends that communication of credentials occurs immediately before the engagement begins for future contracts, so that we can provide as much testing as possible within the allotted time."
    
- **Negative Outcome**: "There was not enough time allocated to this engagement to conduct a thorough review of the application, and the scope became much larger than expected.  It is recommended that more time is allocated to future engagements to provide more comprehensive coverage."


### Technical Summary

A list of all of the key findings in the report, written out with a summary and recommendation for a technical person to learn at a glance what needs to be done.

Should be structured where all findings are grouped, regardless of testing timeline, into common areas:
- User and Privilege Management
- Architecture
- Authorization
- Patch Management
- Integrity and Signatures
- Authentication
- Access Control
- Audit, Log Management and Monitoring
- Traffic and Data Encryption
- Security Misconfigs

Example technical summary for Patch Management:
```
4. Patch Management

Windows and Ubuntu operating systems that are not up to date were
identified. These are shown to be vulnerable to publicly-available
exploits and could result in malicious execution of code, theft
of sensitive information, or cause denial of services which may
impact the infrastructure. Using outdated applications increases the
possibility of an intruder gaining unauthorized access by exploiting
known vulnerabilities. Patch management ought to be improved and
updates should be applied in conjunction with change management.
```

The section should finish with a risk heat map based on vulnerability severity adjusted as appropriate to the client's context, and as agreed upon with a client security risk representative if possible.


### Technical Findings and Recs

Includes the full technical details relating to the penetration test, and what's considered to be the appropriate steps required to address the findings.
Often presented in tabular form providing details of full findings.  Each entry may be 1 specific vuln or cover multiple of the same type.
Likely the major and largest part of the report.   The time and effort spent writing it should reflect its importance.

While this is a technical section, don't assume the audience is made up of penetration testers.
Not everyone will fully understand the nuances of the vulnerabilities reported.
It's better to assume less background knowledge of the audience and give too much info than to do the opposite.

That being said, a brief overview of how an exploit was able to take place should be sufficient compared to a deep technical dive into the root cause.

It's important to note that there might be a need for an attack narrative. This narrative describes, in story format, exactly what happened during the test. This is typically done for a simulated threat engagement, but is also useful at times to describe the more complex exploitation steps required for a regular penetration test. If it is necessary, then writing out the attack path step-by-step, with appropriate screenshots, is generally sufficient. An extended narrative could be placed in an Appendix and referenced from the findings table.

Ex:

| Ref | Risk | Issue Description and Implications | Recommendations |
| ---- | ---- | ---- | ---- |
| 1 | H | Account, Password, and Privilege Management is inadequate.  Account management is the process of provisioning new accounts and removing accounts that are no longer required.  The following issues were identified by performing an analysis of 122,624 user accounts post-compromise: 722 user accounts were configured to never expire; 23,142 users had never logged in; 6 users were members of the domain administrator group; default initial passwords were in use for 968 accounts. | All accounts should have passwords that are enforced by a strict policy.  All accounts with weak passwords should be forced to change them.  All accounts should be set to expire automatically.  Accounts no longer required should be removed. |
| 2 | H | Information enumerated through an anonymous SMB session.  An anonymous SMB session connection was made, and the information gained was then used to gain unauthorized user access as detailed in Appendix E.9. | To prevent information gathering via anonymous SMB sessions: Access to TCP ports 139 and 445 should be restricted based on roles and requirements. Enumeration of SAM accounts should be disabled using the Local Security Policy > Local Policies > Security Options |
| 3 | M | Malicious JavaScript code can be run to silently carry out malicious activity.  A form of this is reflected cross-site scripting (XSS), which occurs when a web application accepts user input with embedded active code and then outputs it into a webpage that is subsequently displayed to a user.  This will cause attacker-injected code to be executed on the user's web browser. XSS attacks can be used to achieve outcomes such as unauthorized access and credential theft, which can in some cases result in reputational and financial damage as a result of bad publicity or fines.  As shown in Appendix E.8, the [client] application is vulnerable to an XSS vulnerability because the username value is displayed on the screen login attempt fails. A proof-of-concept using a maliciously crafted username is provided in Appendix E. | Treat all user input as potentially tainted, and perform proper sanitization through special character filtering.  Adequately encode all user-controlled output when rendering to a page.  Do not include the username in the error message of the application login. |

An issue's severity represents only it's technical severity not it's context-specific business risk.  It can be marked as either a Technical Severity or the client's risk team can be consulted to work together in forming the appropriate risk level including consideration of the unique business impact on the client.

- Start the findings description with a sentence or two describing what the vuln is, why it is dangerous, and what an attacker can accomplish with it.
	Goal is to provide insight into the immediate impact of an attack.

- Describe some of the technical details about the vulnerability at a basic level: what the vulnerability is and how to exploit it.
	Goal is to describe a complex exploit in a way that most technical audiences can understand.

- Include evidence to prove the vulnerability identified is exploitable, along with any further relevant information.
	If simple, can be included inline as per the first entry above.  Otherwise, document in an appendix as shown in the second entry.

Once the details of the vulnerability have been explained, we can describe the specific finding that we have identified in the system or application. We will use the notes that we took during testing and the screenshots that support them to provide a detailed account. Although this is more than a few sentences, we'll want to summarize it in the table and reference an appendix for the full description.

In describing findings:
- Broad solutions should be avoided.  Instead drill down to specifics of the app and business
- Theoretical solutions are not effective in combating a vuln.  A solution should have concrete and practical implementations
- Don't layer multiple steps into a solution.  Each distinct step should be its own solution. 
- Present means of replicating them (in either the body of the report or an appendix)
- Show exactly where the app was affected and how to trigger the vuln
- Provide a full set of steps to replicate findings with screenshots (including things like running w/ admin privs)
- Separate details into two sections:
	- Affected url/ endpoint
	- Method of triggering vuln
- If multiple areas are affected by a vuln, include a reference to each area
- If there are a large amount of similar issues, provide samples w/ a caveat that it's not the only area where the issue occurs (\*rec systemic remediation)

### Appendices, Addt Findings, and References

Things that go here typically don't fit anywhere else in the report or are too lengthy or detailed to include inline.  Includes long lists of compromised users or affected areas, large proof-of-concept code blocks, expanded methodology or technical write-ups, etc.  

A good rule to follow is if it's necessary for the report but would break the flow of the page, put it in an appendix.

A *Further Information* section would be good for things that wouldn't make it in the main write-up, but can provide value to the client like articles that describe the vulnerability in more depth, standards for the remediation recommendation for the client to follow, and other methods of exploitation.

_References_ can be a useful way to provide more insight for the client in areas not directly relevant to the testing we carried out.  Must be the most authoritative sources.