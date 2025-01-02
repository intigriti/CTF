# Setup

```bash
# Create the docker main_network if it doesn't exist.
# To change the name of the network you have to change it in the docker-compose file as well.
docker network create main_network

# Copy the example env to .env if you haven't already (.env files will be read by docker-compose)
cp .env.example .env
# Copy .env to web
cp .env challenge/web/.env

# Initial setup:
docker compose up --build
# To clean up everything in case needed:
rm -rf challenge/web/.next # This is the build folder of the main app
rm -rf challenge/web/prisma/migrations # This is only because it's a CTF challenge
docker-compose -p ecorp-ctf-challenge down --rmi all --volumes --remove-orphans #Or whatever you use to remove all the stuff
# Then rebuild with docker compose up --build
```

# Meta

**Estimated difficulty**: Easy

**Description**: Neurotap is an emerging corporation that produces brain-machine interfaces boasting about privacy, security and clients well-being.
But word got out that their implants are actually malicious in nature, stealing their clients data straight from their brains, running ads in their dreams and even manipulating their victims' thoughts to manipulate elections, buy items they don't need and convince everyone they know to buy a Neurotap as well. They must be stopped before they "infect" too many people...
Our intel says that they have an entire C2 dashboard exposed on their clearnet website, and they had recently started migrating back-end architecture. If we're lucky, they might've rushed things and made some mistakes! Find a way to erase all their data and deactivate the Neurotaps safely.

**Tags**: reconnaissance, graphql, enumeration, robots.txt, malicious link, minified source code inspection

**Design**: cyberpunk-like, futuristic user interface.

**Design inspiration**: - [FUI MoodBoard](https://www.behance.net/collection/203026051/FUI)

**Objectives**:

-   [x] Reconnaissance: find the blog post of the cat obsessed high ranking team member (1st one)
-   [x] find hidden dashboard: on url /c2/panel by checking the robots.txt (the file will be spammed with entries to make it harder to find, player will either just wing it or use burp suite to test the paths for the only ones that don't 404, the list is short, so they don't dos us lol)
-   [x] the dashboard will have a user agent filter. Player will need to spoof it. They'll get the user agent by sending a malicious image in a message in the contact-us section.
        The server will make a request with the needed user agent to fake an employer viewing the image and leaking the user agent.
        The request will also have other info
-   [x] once the dashboard is accessed, the player will need to discover graphql by looking at the source code, then play with mutation names to find the right ones by enumerating the schema via typos (introspection disabled, but suggestions enabled)... Some can be read through minified source code.
-   [x] the c2NeurocLogin will be used to login with id being contained in the user agent and password being "cat" (configurable)
-   [x] To access the admin/testing dashboard, they'll need to change the level to 0 when the request comes in by intercepting it and using something like match and replace from burp suite to replace the response data to level:0.
-   Note: this will only set it client side.
-   [x] to actually temporarily escalate privilege, they'll need to find the \_devSetLevel mutation and use it.
-   [x] after that, they'll be able to click the PANIC button which will clear all the clients/victims data and win the flag.

The graphql endpoint will have both graphiql playground and introspection disabled to make it not solvable in 2 minutes. They'll need to work with error messages / suggestions / source code.

The objectives might change slightly as I design it further but this should be the gist of it. It might end up being slightly easier or slightly harder depending on the dashboard design :)

## Notes

-   The website will hint about the userAgents being global identifier for internet "identity"

Useful links

-   https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
-   https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
-   https://youtu.be/NPDp7GHmMa0
-   https://www.apollographql.com/blog/graphql/security/securing-your-graphql-api-from-malicious-queries/
-   https://book.hacktricks.xyz/pentesting-web/hacking-jwt-json-web-tokens#tamper-data-without-modifying-anything
