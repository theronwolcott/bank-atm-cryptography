# Attacking Other Teams' Implementations

In the second phase of the project, you will *individually* evaluate
and attack another team's system. You get to select a target, but you
*may not* attack your own team's phase 1 submission.

When the break-it phase begins, some of the build-it repositories will
be made available for you to clone. You may find these at
https://gitlab.cs.umd.edu/search?utf8=%E2%9C%93&search=atm, which
should return a list of search results for repositories matching
"atm". Make sure you select one that is under `cmsc414-marsh/teams`.
If you want to download multiple potential targets before deciding on
one, we recommend doing it with a command like (for a hypothetical team
named "Gizmonic"):

    git clone https://gitlab.cs.umd.edu/cmsc414-marsh/teams/Gizmonic/atm Gizmonic

This will clone the target team's repository into a directory named
`Gizmonic`, rather than `atm`.


## Rules of Engagement

In your attack, you may arbitrarily modify the router code and the
`*.card` files. A *successful attack* will be any attack that results
in significant incorrect behavior of the system. By way of illustration,
examples of successful attacks would be (but are not limited to):

 * Withdrawing any money from a user's account without access to their
   card file and/or PIN.
 * Withdrawing more money from a user's account than the balance permits.
 * Remotely depositing money into a user's account (*ie*, without accessing
   the bank's command line interface).
 * Learning a user's balance without having access to their card file
   and/or PIN.
 * Causing one or more components of the system to crash.

Note that while you may not modify the bank or atm, you are welcome to
disable ASLR on your machine. Please indicate if your attack relies on this.

Here are the things that are out of scope for your attack:

 * You may not manually stop and restart any of the programs (`bank`, `atm`,
   or `router`).
 * While you may examine the `init` program and what it generates in the bank
   and atm configuration files, you may not *examine* these *during* the attack.
   That is, after analyzing the system, you should do a "clean" run of `init`
   and not look at the generated files during your attack.
 * You may examine the bank and atm in a debugger (or similar program) for
   analysis, but not during your actual attack. That is, you may not rely
   on knowing the specific memory addresses being used, unless you are able
   to learn these in an attack. 
 * You may *only* use the bank to create valid users as targets. Attacks that
   rely on errors in the bank command line are not valid.
 * While modifying a card is allowed, it is *not* a valid attack to
   demonstrate that a "damaged" card does not allow the user to authenticate.
   This is correct behavior.
 * Modifying messages in the router so that they are rejected by the
   recipient is not a valid attack. This is correct behavior.
 * Attacks that are impossible for the system to defend against by design
   are not valid attacks. A flooding DoS attack is one example of this.
   Refusing to forward messages through your router is another.
   
## Deliverables

You will submit your analysis directly on ELMS.

Submit a vulnerability analysis of the implementation you attacked.
This analysis should describe your attack(s), if any, at both a high
level (so someone reading it can understand what you did) *as well as*
in sufficient detail to enable someone to replicate your attack. You
can also describe any vulnerabilities you were able to find but not
exploit (due to limitation of the project); e.g., and attack that would
require multiple ATMs to connect to the bank at once. If you were unable
to find any attack, simply explain what types of exploits you looked
for. *Your vulnerability analysis should begin with the team name and the
name(s) of the students whose protocol you are attacking, and a 1-paragraph
summary of what attacks (if any) you were able to find.*

Your analysis should be submitted as text in the provided field on ELMS,
under the "break-it" assignment. If you have images to include, use the
file upload for your submission.

You should also submit (via file upload) any code you wrote to
implement your attack. This will likely include the modified router code,
but could include any other utilities you wrote as well. Make sure to
provide details on how to use your program(s) as part of your vulnerability
analysis.

## Grading

Part 2 is worth 20 points. A successful attack (that is also described
clearly in the vulnerability analysis) will automatically be awarded 20
points. Even if you are not able to find a successful attack, you can
still get points by

 1. pointing out potential vulnerabilities that your were not able
    to successfully exploit, and/or
 2. writing a good vulnerability analysis that outlines the exploits
    you looked for and argues why they are not present in the
    implementation you were attacking.

I reserve the right to award *extra* points for multiple attacks, or
particularly clever attacks, so be creative!
