# Web API Starter Template

Welcome to the Web API Starter Template, a robust foundation for building Web APIs using ASP.NET Core. This template provides essential features like user authentication, email verification, rate limiting, and more to kickstart your API development.

## Features

- **Database Integration:** Choose between SQLite and MySQL as your database engine.
- **JWT Authentication:** Secure your API endpoints with JSON Web Tokens (JWT).
- **Rate Limiting:** Implement rate limiting to protect your API from abuse.
- **User Management:** Includes user registration, login, and email verification.
- **Logging:** Utilize a logging system to keep track of important events in your API.
- **CORS Configuration:** Set up Cross-Origin Resource Sharing (CORS) for secure cross-domain requests.
- **Utilities:** Leverage utility functions for common tasks.

## Prerequisites

Before getting started, ensure you have the following installed on your development machine:

- [.NET SDK](https://dotnet.microsoft.com/download/dotnet) (compatible with the project version)
- [Git](https://git-scm.com/downloads)

## Getting Started

1. **Clone the Repository:**

   Clone this repository to your local machine:

git clone https://github.com/NiRo-2/WebApi_StarterTemplate.git

2. **Database Configuration:**

- SQLite: If you choose SQLite, no further configuration is required.
- MySQL: Update the connection string in the `appsettings.json` file with your MySQL server details.

3. **JWT Configuration:**

Configure the JWT settings in the `appsettings.json` file under the `JWT` section.

4. **CORS Configuration:**

Configure allowed CORS origins in the `appsettings.json` file under the `Cors` section.

5. **Passwords Encryption:**

Ensure that sensitive passwords stored in the `appsettings.json` file are encrypted using `EncryptionHelper.EncryptKey` provided by the NrExtrasSolution  repository.

6. **NrExtras Solution Integration:**

To enhance your Web API project, you must use the [NrExtrasSolution  repository](https://github.com/NiRo-2/NrExtrasSolution). It provides essential utility functions, email helpers, and logging capabilities that are integral to this project.

- Clone the NrExtrasSolution  repository:

  ```
  git clone https://github.com/NiRo-2/NrExtrasSolution.git
  ```

- Reference the NrExtrasSolution  project in your Web API project.

- Utilize the utilities, email helpers, and logger provided by NrExtrasSolution  to streamline your development.

7. **Run the Application:**

Run your application using the following command:

dotnet run

Access the API:

Your API will be available at https://localhost:5001 (or a different port if configured).

## Usage

- **User Registration:**

Use the `/api/users/register` endpoint to register a new user.
Verify the user's email using the provided email confirmation link.

- **User Login:**

Authenticate users using the `/api/auth/login` endpoint and obtain a JWT token.
Include the JWT token in the Authorization header for protected endpoints.

- **User Logout:**

Use the `/api/auth/logout` endpoint to log out a user and invalidate their token.

- **Rate Limiting:**

Configure rate limiting policies in the `appsettings.json` file under the `IpRateLimitPolicies` section.

- **Customization:**

Customize and expand the API according to your project requirements.

## Contributing

We welcome contributions to improve and expand this starter template. Feel free to submit issues or pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
