# ezxmldsig-js

Bibliothèque Node.js, pendant de la bibliothèque PHP ezxmldsig : mêmes jetons
XML signés et chiffrés, interopérables avec elle dans les deux sens. Paquet npm
`@webcoder31/ezxmldsig`, projet Cairn EZXJS.

## Point de départ

Le ticket **EZXJS-1** (`cairn show EZXJS-1 --full`) contient le but, le format,
l'interface, les exigences de sécurité, les tests, la livraison et les
décisions à prendre avec l'humain avant de coder.

## La référence

La version PHP définit le comportement attendu : `~/Code/projects/ezxmldsig`
(GitHub `webcoder31/ezxmldsig`, version 1.2.0). Pour toute question de format
ou de vérification, la réponse est dans son code (`src/XMLDSigToken.php`), ses
tests et son README, pas dans une supposition. Ne pas modifier ce dépôt depuis
ce projet : ce qui doit y changer passe par un ticket du projet Cairn EZXML.
