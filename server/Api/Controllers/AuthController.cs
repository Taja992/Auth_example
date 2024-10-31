using System.ComponentModel.DataAnnotations;
using DataAccess.Entities;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Service;
using Service.Auth.Dto;
using Service.Security;

namespace Api.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
//     [HttpPost]
//     [Route("login")]
//     public async Task<LoginResponse> Login(
//         [FromServices] SignInManager<User> signInManager,
//         [FromServices] IValidator<LoginRequest> validator,
//         [FromServices] ITokenClaimsService tokenClaimsService,
//         [FromBody] LoginRequest data
//     )
//     {
//         // Validate login
//         var validationResult = await validator.ValidateAsync(data);
//         if (!validationResult.IsValid)
//         {
//             throw new Exception("Validation failed");
//         }
//
//         // Attempt to Auth
//         var result = await signInManager.PasswordSignInAsync(data.Email, data.Password, isPersistent: false,
//             lockoutOnFailure: false);
//         if (!result.Succeeded)
//         {
//             throw new AuthenticationError();
//         }
//
//         var token = await tokenClaimsService.GetTokenAsync(data.Email);
//
//         // return success
//         return new LoginResponse(Jwt: token);
//     
// }

    [HttpPost]
    [Route("login")]
    public async Task<LoginResponse> Login(
        [FromServices] UserManager<User> userManager,
        [FromServices] IValidator<LoginRequest> validator,
        [FromServices] ITokenClaimsService tokenClaimsService,
        [FromBody] LoginRequest data
    )
    {
        await validator.ValidateAndThrowAsync(data);
        var user = await userManager.FindByEmailAsync(data.Email);
        if (user == null || !await userManager.CheckPasswordAsync(user, data.Password))
        {
            throw new AuthenticationError();
        }

        var token = await tokenClaimsService.GetTokenAsync(data.Email);

        return new LoginResponse(Jwt: token);
    }



    [HttpPost]
    [Route("register")]
    public async Task<RegisterResponse> Register(
        IOptions<AppOptions> options,
        [FromServices] UserManager<User> userManager,
        [FromServices] IValidator<RegisterRequest> validator,
        [FromBody] RegisterRequest data
    )
    {

        var validateRegister = await validator.ValidateAsync(data);
        if (!validateRegister.IsValid)
        {
            throw new Exception("Validation Failed");
        }

        // Create new user
        var newUser = new User()
        {
            Email = data.Email,
            UserName = data.Name
        };

        var result = await userManager.CreateAsync(newUser, data.Password);
        if (!result.Succeeded)
        {
            throw new ValidationError(
                result.Errors.ToDictionary(x => x.Code, x => new[] { x.Description })
            );
        }

        await userManager.AddToRoleAsync(newUser, Role.Reader);

        
        // Return success response
        return new RegisterResponse(Email: newUser.Email, Name: newUser.UserName);
    }

    
    [HttpPost]
    [Route("logout")]
    public async Task<IResult> Logout([FromServices] SignInManager<User> signInManager)
    {
        await signInManager.SignOutAsync();
        return Results.Ok();
    }

    [HttpGet]
    [Route("userinfo")]
    public async Task<AuthUserInfo> UserInfo([FromServices] UserManager<User> userManager)
    {
        var username = (HttpContext.User.Identity?.Name) ?? throw new AuthenticationError();
        var user = await userManager.FindByNameAsync(username) ?? throw new AuthenticationError();
        var roles = await userManager.GetRolesAsync(user);
        var isAdmin = roles.Contains(Role.Admin);
        var canPublish = roles.Contains(Role.Editor) || isAdmin;
        return new AuthUserInfo(username, isAdmin, canPublish);
    }
}
