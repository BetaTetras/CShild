# 🛡️ CShild CLI – Avancement

| État | Catégorie         | Commande                                            |
|:----:|-------------------|-----------------------------------------------------|
| ❌ | ⚙️ Général         | `CShild`                                            |
| ✅ | ⚙️ Général         | `CShild --info`                                     |
| ✅ | ⚙️ Général         | `CShild --help`                                     |
| ✅ | ⚙️ Général         | `CShild --version`                                  |
| ✅ | 🔐 Coffres         | `CShild init <vault>`                               |
| ✅ | 🔐 Coffres         | `CShild vaults`                                     |
| ✅ | 🔐 Coffres         | `CShild password [--vault]`                         |
| ❌ | ➕ Création        | `CShild crt [--vault] --app --id`                |
| ❌ | ➕ Création        | `CShild crt [--vault] --app --id --note`         |
| ❌ | ➕ Création        | `CShild crt [--vault] --app --id --tags,...`     |
| ❌ | 🗑️ Suppression     | `CShild dlt [--vault] --app --id`                |
| ❌ | 🗑️ Suppression     | `CShild dlt [--vault] --app`                     |
| ❌ | 🗑️ Suppression     | `CShild dlt [--vault] --app [--id] --yes`        |
| ❌ | ✏️ Modification    | `CShild mdf [--vault] --app --rename-app`        |
| ❌ | ✏️ Modification    | `CShild mdf [--vault] --app --id --rename-id`    |
| ❌ | ✏️ Modification    | `CShild mdf [--vault] --app --id --set-password` |
| ❌ | ✏️ Modification    | `CShild mdf [--vault] --app --id --note`         |
| ❌ | ✏️ Modification    | `CShild mdf [--vault] --app --id --add-tag`      |
| ❌ | ✏️ Modification    | `CShild mdf [--vault] --app --id --remove-tag`   |
| ❌ | 👁️ Affichage       | `CShild shw [--vault]`                             |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --app`                       |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --id`                        |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --app --id`                  |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --tag`                       |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --table [--app]`             |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --app --id --reveal`         |
| ❌ | 👁️ Affichage       | `CShild shw [--vault] --app --id --copy`           |
| ❌ | 🎲 Générateur      | `CShild gen`                                   |
| ❌ | 🎲 Générateur      | `CShild gen --length`                          |
| ❌ | 🎲 Générateur      | `CShild gen --length --no-symbols`             |

Légende : ✅ fait · 🚧 en cours · ❌ à faire