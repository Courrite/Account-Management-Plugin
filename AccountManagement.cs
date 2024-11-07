//////////////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                  ,----,                  //
//                     ,----..                                                    ,/   .`|                  //
//        ,----..     /   /   \                ,-.----.   ,-.----.     ,---,    ,`   .'  :   ,---,.         //
//       /   /   \   /   .     :          ,--, \    /  \  \    /  \ ,`--.' |  ;    ;     / ,'  .' |         //
//         :     : .   /   ;.  \       ,'_ /| ;   :    \ ;   :    \|   :  :.'___,/    ,',---.'   |          //
//      .   |  ;. /.   ;   /  ` ;  .--. |  | : |   | .\ : |   | .\ ::   |  '|    :     | |   |   .'         //
//      .   ; /--` ;   |  ; \ ; |,'_ /| :  . | .   : |: | .   : |: ||   :  |;    |.';  ; :   :  |-,         //
//      ;   | ;    |   :  | ; | '|  ' | |  . . |   |  \ : |   |  \ :'   '  ;`----'  |  | :   |  ;/|         //
//      |   : |    .   |  ' ' ' :|  | ' |  | | |   : .  / |   : .  /|   |  |    '   :  ; |   :   .'         //
//      .   | '___ '   ;  \; /  |:  | | :  ' ; ;   | |  \ ;   | |  \'   :  ;    |   |  ' |   |  |-,         //
//      '   ; : .'| \   \  ',  / |  ; ' |  | ' |   | ;\  \|   | ;\  \   |  '    '   :  | '   :  ;/|         //
//      '   | '/  :  ;   :    /  :  | : ;  ; | :   ' | \.':   ' | \.'   :  |    ;   |.'  |   |    \         //
//      |   :    /    \   \ .'   '  :  `--'   \:   : :-'  :   : :-' ;   |.'     '---'    |   :   .'         //
//       \   \ .'      `---`     :  ,      .-./|   |.'    |   |.'   '---'                |   | ,'           //
//        `---`                   `--`----'    `---'      `---'                          `----'             //
//                                                                                                          //
//                                      GNU GENERAL PUBLIC LICENSE                                          //
//                                       Version 3, 29 June 2007                                            //
//                                                                                                          //
//                  Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>                    //
//                      Everyone is permitted to copy and distribute verbatim copies                        //
//                        of this license document, but changing it is not allowed.                         //
//                                                                                                          //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Xna.Framework;
using Terraria;
using TerrariaApi.Server;
using TShockAPI;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using MongoDB.Driver;
using Newtonsoft.Json;
using System.Runtime.Serialization;
using BCrypt;

namespace AccountManagementPlugin
{
    [ApiVersion(2, 1)]
    public class AccountManagement : TerrariaPlugin
    {
        public override string Name => "AccountManagement";
        public override string Author => "Courrite";
        public override Version Version => new Version(1, 0, 0, 1);
        public override string Description => "Manage user accounts with MongoDB.";

        private readonly UserService _userService;
        private readonly RankService _rankService;
        private readonly SuspensionService _suspensionService;
        private readonly PermissionService _permissionService;
        private readonly WarningService _warningService;
        private readonly ModLogService _modLogService;
        private readonly MuteService _muteService;
        private readonly IdentificationService _identificationService;

        private Config? _config;

        public AccountManagement(Main game) : base(game)
        {
            _config = LoadConfiguration();
            var dbConnection = new MongoDBConnection(_config.Database.ConnectionString, _config.Database.DatabaseName, this);
            _userService = new UserService(dbConnection);
            _rankService = new RankService(dbConnection);
            _suspensionService = new SuspensionService(dbConnection);
            _permissionService = new PermissionService();
            _warningService = new WarningService(dbConnection);
            _modLogService = new ModLogService(dbConnection);
            _muteService = new MuteService(dbConnection);
            _identificationService = new IdentificationService();
        }

        public override void Initialize()
        {
            Commands.ChatCommands.Clear();

            RegisterCommand("help", Help);
            RegisterCommand("register", Register);
            RegisterCommand("login", Login);
            RegisterCommand("logout", Logout);
            RegisterCommand("info", Info, "info");
            RegisterCommand("changepassword", ChangePassword, "changepassword");
            RegisterCommand("changename", ChangeUsername, "changename");
            RegisterCommand("bal", Balance, "bal");
            RegisterCommand("w", Whisper, "w");
            RegisterCommand("report", Report, "report");
            RegisterCommand("priorityreport", PriorityReport, "priorityreport");
            RegisterCommand("warn", Warn, "warn");
            RegisterCommand("warnings", Warnings, "warnings");
            RegisterCommand("removewarn", RemoveWarn, "removewarn");
            RegisterCommand("clearwarns", ClearWarns, "clearwarns");
            RegisterCommand("modlogs", ModLogs, "modlogs");
            RegisterCommand("unmute", Unmute, "unmute");
            RegisterCommand("mute", Mute, "mute");
            RegisterCommand("kick", Kick, "kick");
            RegisterCommand("changerank", ChangeRank, "changerank");
            RegisterCommand("changebal", ChangeBal, "changebal");
            RegisterCommand("suspend", Suspend, "suspend");
            RegisterCommand("unsuspend", Unsuspend, "unsuspend");
            RegisterCommand("deleteaccount", DeleteAccount, "deleteaccount");
            RegisterCommand("exit", Exit, "exit");

            TerrariaApi.Server.ServerApi.Hooks.ServerJoin.Register(this, OnPlayerJoin);
            TerrariaApi.Server.ServerApi.Hooks.ServerChat.Register(this, OnChat);

            _config = LoadConfiguration();
        }

        // Command Preprocessors

        private async void ExecuteCommand(CommandArgs args, string permissionRequired, Action<CommandArgs> commandAction)
        {
            bool allowed = await _permissionService.CheckIfRankHasPermission(args, permissionRequired, _userService, _rankService);
            if (allowed == false)
            {
                args.Player.SendErrorMessage("You do not have permission to execute this command.");
                return;
            }

            commandAction(args);
        }

        private void RegisterCommand(string commandName, Action<CommandArgs> action, string permission = null)
        {
            Commands.ChatCommands.Add(new Command(args => ExecuteCommand(args, permission, action), commandName));
        }

        // Command Functions

        private async void Help(CommandArgs args)
        {
            var helpMessage = new StringBuilder();
            helpMessage.AppendLine("Available Commands:");

            var commands = new Dictionary<string, (string description, string permission)>
    {
        { "/help", ("Show this help message.", null) },
        { "/register <username> <password>", ("Register a new account.", null) },
        { "/login <username> <password>", ("Log into your account.", null) },
        { "/logout", ("Log out of your account.", null) },
        { "/info <username/id>", ("View information about a user.", "info") },
        { "/changepassword <oldpassword> <newpassword>", ("Change your password.", "changepassword") },
        { "/changename <password> <newname>", ("Change your username.", "changename") },
        { "/changerank <username> <newrank>", ("Change a user's rank (requires permission).", "changerank") },
        { "/changebal <username> <amount>", ("Change a user's balance (requires permission).", "changebal") },
        { "/suspend <username> <reason> <seconds>", ("Suspend a user (requires permission).", "suspend") },
        { "/unsuspend <username>", ("Unsuspend a user (requires permission).", "unsuspend") },
        { "/warn <username> <reason>", ("Issue a warning to a user (requires permission).", "warn") },
        { "/warnings <username>", ("View warnings for a user (requires permission).", "warnings") },
        { "/modlogs <username>", ("View mod logs for a user (requires permission).", "modlogs") },
        { "/mute <username> <reason> <seconds>", ("Mute a user (requires permission).", "mute") },
        { "/unmute <username>", ("Unmute a user (requires permission).", "unmute") },
        { "/kick <username> <reason>", ("Kick a user from the server (requires permission).", "kick") },
        { "/exit", ("Exit the server.", "exit") }
    };

            foreach (var command in commands)
            {
                if (await _permissionService.CheckIfRankHasPermission(args, command.Value.permission, _userService, _rankService))
                {
                    helpMessage.AppendLine($"{command.Key} - {command.Value.description}");
                }
            }

            args.Player.SendInfoMessage(helpMessage.ToString());
        }

        private async void Register(CommandArgs args)
        {
            var player = args.Player;
            var playerUUID = player.UUID;

            if (player.GetData<string>("Username") != null)
            {
                player.SendErrorMessage("You are already logged in.");
                return;
            }

            if (args.Parameters.Count < 2)
            {
                player.SendErrorMessage("Usage: register <username> <password>");
                return;
            }

            string username = args.Parameters[0];
            string password = args.Parameters[1];

            var (success, message) = await _userService.CreateAccountDocument(playerUUID, username, password, _identificationService);
            if (success)
            {
                player.SendSuccessMessage(message);
                player.SetData("Username", username);
            }
            else
            {
                player.SendErrorMessage(message);
            }
        }

        private async void Login(CommandArgs args)
        {
            var player = args.Player;
            var playerUUID = player.GetData<string>("UUID");

            if (player.GetData<string>("Username") != null)
            {
                player.SendErrorMessage("You are already logged in.");
                return;
            }

            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: login <username> <password>");
                return;
            }

            string username = args.Parameters[0];
            string password = args.Parameters[1];

            Suspension suspension = await _suspensionService.RetrieveSuspensionByAccountUsername(username);
            if (suspension != null)
            {
                player.SendErrorMessage("Your account is suspended. You cannot join the server.");
                player.Disconnect("You're suspended for  " + suspension.Reason + " until " + suspension.ExpirationDate + ".");
                bool uuidAdded = await _suspensionService.AddAssociatedUUID(username, playerUUID);
                if (!uuidAdded)
                {
                    player.Disconnect("An error has occured. Please rejoin.");
                }
            }

            var (success, message) = await _userService.VerifyAccountPassword(username, password, new IdentificationService());
            if (success)
            {
                player.SendSuccessMessage(message);
                player.SendSuccessMessage("Successfully logged in!");
                player.SetData("Username", username);
            }
            else
            {
                args.Player.SendErrorMessage(message);
            }
        }

        private async void Logout(CommandArgs args)
        {
            var player = args.Player;
            string username = args.Player.GetData<string>("Username");
            if (string.IsNullOrEmpty(username))
            {
                args.Player.SendErrorMessage("You are not logged in.");
                return;
            }

            player.RemoveData("Username");
            player.SendSuccessMessage("Logged out successfully.");
        }

        private async void Info(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: info <user> or <account id>");
                return;
            }

            var player = args.Player;

            string target = args.Parameters[0];
            Account account;

            if (int.TryParse(target, out int accountId))
            {
                account = await _userService.RetrieveAccountByID(accountId);
            }
            else
            {
                account = await _userService.RetrieveAccountByUsername(target);
            }

            if (account != null)
            {
                args.Player.SendSuccessMessage($"Account ID: {account.AccountID}, Username: {account.Username}, Rank: {account.Rank}, Balance: {account.Balance}");
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void ChangePassword(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: changepassword <oldpassword> <newpassword>");
                return;
            }

            string oldPassword = args.Parameters[0];
            string newPassword = args.Parameters[1];
            string username = args.Player.GetData<string>("Username");

            if (string.IsNullOrEmpty(username))
            {
                args.Player.SendErrorMessage("You must be logged in to change your password.");
                return;
            }

            var (success, message) = await _userService.ChangeAccountPassword(username, oldPassword, newPassword, new IdentificationService());
            if (success)
            {
                args.Player.SendSuccessMessage(message);
            }
            else
            {
                args.Player.SendErrorMessage(message);
            }
        }

        private async void ChangeUsername(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: changeusername <oldusername> <newusername> <password>");
                return;
            }

            string oldUsername = args.Parameters[0];
            string newUsername = args.Parameters[1];
            string password = args.Parameters[2];
            string username = args.Player.GetData<string>("Username");

            if (string.IsNullOrEmpty(username) || username != oldUsername)
            {
                args.Player.SendErrorMessage("You can only change your own username.");
                return;
            }

            var (success, message) = await _userService.ChangeAccountName(username, password, newUsername, new IdentificationService());
            if (success)
            {
                args.Player.SendSuccessMessage(message);
                args.Player.SetData("Username", newUsername);
            }
            else
            {
                args.Player.SendErrorMessage(message);
            }
        }

        private async void Balance(CommandArgs args)
        {
            string username = args.Player.GetData<string>("Username");
            if (string.IsNullOrEmpty(username))
            {
                args.Player.SendErrorMessage("You must be logged in to check your balance.");
                return;
            }

            Account account = await _userService.RetrieveAccountByUsername(username);
            if (account != null)
            {
                args.Player.SendSuccessMessage($"Your balance is: {account.Balance}");
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Whisper(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: /whisper <player> <message>");
                return;
            }

            string targetUsername = args.Parameters[0];
            string message = string.Join(" ", args.Parameters.Skip(1));

            TSPlayer targetPlayer = TShock.Players.FirstOrDefault(p => p != null && p.Name.Equals(targetUsername, StringComparison.OrdinalIgnoreCase));

            if (targetPlayer == null)
            {
                args.Player.SendErrorMessage($"Player '{targetUsername}' not found.");
                return;
            }

            targetPlayer.SendMessage($"[Whisper] {args.Player.Name}: {message}", Color.LightGreen);
            args.Player.SendMessage($"You whispered to {targetPlayer.Name}: {message}", Color.LightGreen);
        }

        private async void Report(CommandArgs args)
        {
            if (args == null || args.Parameters == null)
            {
                return;
            }

            if (args.Parameters.Count < 3)
            {
                args.Player?.SendErrorMessage("Usage: report <username> <reason> <proof> (if no proof then put \"N/A\")");
                return;
            }

            string targetUsername = args.Parameters[0];
            string reason = args.Parameters[1];
            string proof = args.Parameters[2];

            if (_config == null || _config.HTTP == null || string.IsNullOrEmpty(_config.HTTP.ReportsChannelWebhook))
            {
                args.Player?.SendErrorMessage(_config.HTTP.ReportsChannelWebhook);
                args.Player?.SendErrorMessage("Configuration is not set up correctly.");
                return;
            }

            var httpService = new HTTPService();
            var (success, responseMessage) = await httpService.SendReportAsync(_config.HTTP.ReportsChannelWebhook, targetUsername, reason, proof, args.Player.Name);

            if (success)
            {
                args.Player?.SendSuccessMessage("Your report has been submitted successfully.");
            }
            else
            {
                args.Player?.SendErrorMessage($"There was an error submitting your report: {responseMessage}");
            }

            httpService.Dispose();
        }

        private async void PriorityReport(CommandArgs args)
        {
            if (args == null || args.Parameters == null)
            {
                return;
            }

            if (args.Parameters.Count < 3)
            {
                args.Player?.SendErrorMessage("Usage: report <username> <reason> <proof> (if no proof then put \"N/A\")");
                return;
            }

            string targetUsername = args.Parameters[0];
            string reason = args.Parameters[1];
            string proof = args.Parameters[2];

            if (_config == null || _config.HTTP == null || string.IsNullOrEmpty(_config.HTTP.ReportsChannelWebhook))
            {
                args.Player?.SendErrorMessage("Configuration is not set up correctly.");
                return;
            }

            var httpService = new HTTPService();
            var (success, responseMessage) = await httpService.SendReportAsync(_config.HTTP.PriorityReportsChannelWebhook, targetUsername, reason, proof, args.Player.Name);

            if (success)
            {
                args.Player?.SendSuccessMessage("Your report has been submitted successfully.");
            }
            else
            {
                args.Player?.SendErrorMessage($"There was an error submitting your report: {responseMessage}");
            }

            httpService.Dispose();
        }

        private async void Warn(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: warn <username> <reason>");
                return;
            }

            string target = args.Parameters[0];
            string reason = string.Join(" ", args.Parameters.Skip(1));

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                var (success, message) = await _warningService.IssueWarning(args, target, reason, _userService, _suspensionService);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, target, reason, "Warn", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Warnings(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: warnings <username>");
                return;
            }

            string target = args.Parameters[0];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                List<Warning> warnings = await _warningService.RetrieveWarningsByAccountUsername(target);
                if (warnings != null)
                {
                    foreach (var warning in warnings)
                    {
                        args.Player.SendInfoMessage($"Warning ID: {warning.WarningID}\nReason: {warning.Reason}\nIssued At: {warning.IssuedAt}");
                    }
                }
                else
                {
                    args.Player.SendErrorMessage("No warnings found for this account.");
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void RemoveWarn(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: removewarn <user> <uuid>");
                return;
            }

            string target = args.Parameters[0];
            string uuid = args.Parameters[1];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                var (success, message) = await _warningService.RemoveWarning(args, target, uuid, _userService);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, target, $"Removed warning ID: {uuid}", "RemoveWarn", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void ClearWarns(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: clearwarns <username>");
                return;
            }

            string target = args.Parameters[0];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                List<Warning> warnings = await _warningService.RetrieveWarningsByAccountUsername(target);
                if (warnings != null)
                {
                    foreach (var warning in warnings)
                    {
                        await _warningService.RemoveWarning(args, target, warning.WarningID, _userService);
                    }
                    args.Player.SendSuccessMessage("All warnings cleared successfully.");

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, target, "All warnings cleared", "ClearWarns", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage("No warnings found for this account.");
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void ModLogs(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: modlogs <user>");
                return;
            }

            string target = args.Parameters[0];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                List<ModCase> modLogs = await _modLogService.RetrieveModLogsByUsername(target);
                if (modLogs != null)
                {
                    foreach (var modLog in modLogs)
                    {
                        args.Player.SendInfoMessage($"Case ID: {modLog.CaseID}\nReason: {modLog.Reason}\nAction: {modLog.Action}\nIssued At: {modLog.IssuedAt}");
                    }
                }
                else
                {
                    args.Player.SendErrorMessage("No mod logs found for this player.");
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Unmute(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: unmute <username>");
                return;
            }

            string target = args.Parameters[0];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                var (success, message) = await _muteService.RevokeMute(args, target, _userService);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, target, "Unmuted", "Unmute", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Mute(CommandArgs args)
        {
            if (args.Parameters.Count < 3)
            {
                args.Player.SendErrorMessage("Usage: mute <username> <reason> <seconds>");
                return;
            }

            string target = args.Parameters[0];
            string reason = args.Parameters[1];
            string length = args.Parameters[2];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                var (success, message) = await _muteService.IssueMute(args, target, reason, length, _userService, this);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, target, reason, "Mute", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Kick(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: kick <player> <reason>");
                return;
            }

            string targetUsername = args.Parameters[0];
            string reason = args.Parameters.Count > 1 ? string.Join(" ", args.Parameters.Skip(1)) : "No reason specified";

            Account targetAccount = await _userService.RetrieveAccountByUsername(targetUsername);
            if (targetAccount != null)
            {
                TSPlayer targetPlayer = TShock.Players.FirstOrDefault(p => p != null && p.Name.Equals(targetUsername, StringComparison.OrdinalIgnoreCase));
                if (targetPlayer != null)
                {
                    targetPlayer.Disconnect("You have been kicked from the server by an administrator for " + reason + ".");
                    args.Player.SendSuccessMessage($"Player {targetUsername} has been kicked from the server.");

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, targetUsername, reason, "Kick", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage("Player is not currently online.");
                }
            }
            else
            {
                args.Player.SendErrorMessage("Player not found.");
            }
        }

        private async void ChangeRank(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: changerank <username> <newrank>");
                return;
            }

            string targetUsername = args.Parameters[0];
            if (!int.TryParse(args.Parameters[1], out int newRank))
            {
                args.Player.SendErrorMessage("Invalid rank specified. Please provide a valid rank ID.");
                return;
            }

            Account targetAccount = await _userService.RetrieveAccountByUsername(targetUsername);
            if (targetAccount != null)
            {
                var (success, message) = await _userService.ChangeAccountRank(targetAccount.AccountID, newRank);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void ChangeBal(CommandArgs args)
        {
            if (args.Parameters.Count < 2)
            {
                args.Player.SendErrorMessage("Usage: changebal <username> <amount>");
                return;
            }

            string targetUsername = args.Parameters[0];
            if (!int.TryParse(args.Parameters[1], out int amount))
            {
                args.Player.SendErrorMessage("Invalid amount specified. Please provide a valid number.");
                return;
            }

            Account targetAccount = await _userService.RetrieveAccountByUsername(targetUsername);
            if (targetAccount != null)
            {
                var (success, message) = await _userService.ChangeAccountBalance(targetAccount.AccountID, amount);
                if (success)
                {
                    args.Player.SendSuccessMessage($"Successfully changed {targetUsername}'s balance to {amount}.");
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Suspend(CommandArgs args)
        {
            if (args.Parameters.Count < 3)
            {
                args.Player.SendErrorMessage("Usage: suspend <username> <reason> <seconds>");
                return;
            }

            string target = args.Parameters[0];
            string reason = args.Parameters[1];
            string timeString = args.Parameters[2];

            if (!int.TryParse(timeString, out int seconds) || seconds <= 0)
            {
                args.Player.SendErrorMessage("Please provide a valid positive number of seconds.");
                return;
            }

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                var (success, message) = await _suspensionService.SuspendAccount(args, target, reason, timeString, this, _userService);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);

                    var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, target, reason, "Suspend", _userService);
                    if (!logSuccess)
                    {
                        args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                    }
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Unsuspend(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: unsuspend <username>");
                return;
            }

            string targetUsername = args.Parameters[0];

            Suspension suspension = await _suspensionService.RetrieveSuspensionByAccountUsername(targetUsername);
            if (suspension == null)
            {
                args.Player.SendErrorMessage("Account is not suspended.");
                return;
            }

            var (success, message) = await _suspensionService.UnsuspendAccount(targetUsername, _userService);
            if (success)
            {
                args.Player.SendSuccessMessage(message);

                var (logSuccess, logMessage) = await _modLogService.IssueModLog(args, targetUsername, "Unsuspended", "Unsuspend", _userService);
                if (!logSuccess)
                {
                    args.Player.SendErrorMessage("Failed to create mod log: " + logMessage);
                }
            }
            else
            {
                args.Player.SendErrorMessage(message);
            }
        }

        private async void DeleteAccount(CommandArgs args)
        {
            if (args.Parameters.Count < 1)
            {
                args.Player.SendErrorMessage("Usage: deleteaccount <username>");
                return;
            }

            string target = args.Parameters[0];

            Account targetAccount = await _userService.RetrieveAccountByUsername(target);
            if (targetAccount != null)
            {
                var (success, message) = await _userService.DeleteAccountDocument(targetAccount.AccountID);
                if (success)
                {
                    args.Player.SendSuccessMessage(message);
                }
                else
                {
                    args.Player.SendErrorMessage(message);
                }
            }
            else
            {
                args.Player.SendErrorMessage("Account not found.");
            }
        }

        private async void Exit(CommandArgs args)
        {
            Environment.Exit(0);
        }

        // Hooks

        private async void OnPlayerJoin(JoinEventArgs args)
        {
            var player = TShock.Players[args.Who];
            var playerUUID = player.UUID;
            player.SetData("UUID", playerUUID);

            await Task.Delay(1000);

            var account = await _userService.RetrieveAccountByUUID(playerUUID);
            if (account != null)
            {
                Suspension uuidsuspension = await _suspensionService.RetrieveSuspensionByAccountID(account.AccountID);

                if (uuidsuspension != null)
                {
                    if (DateTime.Compare(uuidsuspension.ExpirationDate, DateTime.UtcNow) > 0)
                    {
                        var (success, message) = await _suspensionService.UnsuspendAccount(account.Username, _userService);
                        if (success)
                        {
                            player.SendSuccessMessage(message);
                            player.SendInfoMessage("Your account's suspension has expired, you may now join the server again. Don't do what you did to get yourself suspended.");
                        }
                        return;
                    }
                    player.SendErrorMessage("Your account is suspended. You cannot join the server.");
                    player.Disconnect("You're suspended for " + uuidsuspension.Reason + " until " + uuidsuspension.ExpirationDate + ".");
                    return;
                }
            }
        }

        private async void OnChat(ServerChatEventArgs args)
        {
            var player = TShock.Players[args.Who];
            string username = player.GetData<string>("Username");

            string message = args.Text.Trim();
            if (message.StartsWith("/"))
            {
                return;
            }

            var account = await _userService.RetrieveAccountByUsername(username);
            if (account != null)
            {
                var mute = await _muteService.RetrieveMuteByUsername(username);
                if (mute != null)
                {
                    player.SendErrorMessage("You are muted!\nReason:" + mute.Reason + "\nTill:" + mute.ExpirationDate);
                    args.Handled = true;
                    return;
                }
            }
        }

        // Services

        public class UserService
        {
            private readonly IMongoCollection<Account> _userCollection;

            public UserService(MongoDBConnection dbConnection)
            {
                _userCollection = dbConnection.Accounts;
            }

            public async Task<(bool success, string message)> CreateAccountDocument(string uuid, string username, string password, IdentificationService identificationService)
            {
                Account account = await RetrieveAccountByUsername(username);
                if (account != null) return (false, "Account already exists.");

                var lastAccount = await _userCollection.Find(Builders<Account>.Filter.Empty)
                    .Sort(Builders<Account>.Sort.Descending("AccountID"))
                    .Limit(1)
                    .FirstOrDefaultAsync();

                int newId = (lastAccount?.AccountID ?? 0) + 1;

                var newAccount = new Account
                {
                    AccountID = newId,
                    PlayerUUID = uuid,
                    Username = username,
                    Password = identificationService.HashPassword(password),
                    RegistrationDate = DateTime.UtcNow,
                    Rank = 1,
                    Balance = 0,
                };

                await _userCollection.InsertOneAsync(newAccount);

                return (true, "Account created successfully.");
            }

            public async Task<bool> LoginUser(string username, string password, IdentificationService identificationService)
            {
                Account account = await RetrieveAccountByUsername(username);
                if (account == null) return false;

                return identificationService.VerifyPassword(password, account.Password);
            }

            public async Task<(bool success, string message)> DeleteAccountDocument(int id)
            {
                Account account = await RetrieveAccountByID(id);
                if (account == null) return (false, "Account not found.");

                await _userCollection.DeleteOneAsync(a => a.AccountID == account.AccountID);

                return (true, "Account deleted successfully.");
            }

            public async Task<(bool success, string message)> VerifyAccountPassword(string username, string password, IdentificationService identificationService)
            {
                Account account = await RetrieveAccountByUsername(username);
                if (account == null) return (false, "Account not found.");

                return (identificationService.VerifyPassword(password, account.Password), "Password has been validated.");
            }

            public async Task<(bool success, string message)> ChangeAccountPassword(string username, string oldPassword, string newPassword, IdentificationService identificationService)
            {
                Account account = await RetrieveAccountByUsername(username);
                if (account == null) return (false, "Account not found.");

                if (!identificationService.VerifyPassword(oldPassword, account.Password)) return (false, "Old password is incorrect.");

                account.Password = identificationService.HashPassword(newPassword);
                await _userCollection.ReplaceOneAsync(a => a.Username == username, account);
                return (true, "Password changed successfully.");
            }

            public async Task<(bool success, string message)> ChangeAccountName(string username, string password, string newName, IdentificationService identificationService)
            {
                Account account = await RetrieveAccountByUsername(username);
                if (account == null) return (false, "Account not found.");

                if (!identificationService.VerifyPassword(password, account.Password)) return (false, "Password is incorrect.");

                account.Username = newName;
                await _userCollection.ReplaceOneAsync(a => a.Username == username, account);
                return (true, "Username changed successfully.");
            }

            public async Task<(bool success, string message)> ChangeAccountRank(int id, int newRank)
            {
                Account account = await RetrieveAccountByID(id);
                if (account == null) return (false, "Account not found.");

                account.Rank = newRank;
                await _userCollection.ReplaceOneAsync(a => a.AccountID == id, account);
                return (true, $"Successfully changed {account.Username}'s rank to {newRank}.");
            }

            public async Task<(bool success, string message)> ChangeAccountBalance(int id, int newBalance)
            {
                Account account = await RetrieveAccountByID(id);
                if (account == null) return (false, "Account not found.");

                account.Balance = newBalance;
                await _userCollection.ReplaceOneAsync(a => a.AccountID == id, account);
                return (true, $"Successfully changed {account.Username}'s balance to {newBalance}.");
            }

            public async Task<Account> RetrieveAccountByUsername(string username)
            {
                Account account = await _userCollection.Find(a => a.Username == username).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }
                return account;
            }

            public async Task<Account> RetrieveAccountByID(int id)
            {
                Account account = await _userCollection.Find(a => a.AccountID == id).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }
                return account;
            }

            public async Task<Account> RetrieveAccountByUUID(string uuid)
            {
                Account account = await _userCollection.Find(a => a.PlayerUUID == uuid).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }
                return account;
            }
        }

        public class RankService
        {
            private readonly IMongoCollection<Rank> _rankService;

            public RankService(MongoDBConnection dbConnection)
            {
                _rankService = dbConnection.Ranks;
            }

            public async Task<List<Rank>> RetrieveRanksInCollection()
            {
                return await _rankService.Find(Builders<Rank>.Filter.Empty).ToListAsync();
            }
        }

        public class PermissionService
        {
            public async Task<bool> CheckIfRankHasPermission(CommandArgs args, string permission, UserService userService, RankService rankService)
            {
                if (string.IsNullOrEmpty(permission))
                {
                    return true;
                }

                string username = args.Player.GetData<string>("Username");
                if (username == null)
                {
                    return false;
                }

                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return false;
                }

                Rank? rank = rankService.RetrieveRanksInCollection().Result.FirstOrDefault(r => r.RankID == account.Rank);
                if (rank == null)
                {
                    return false;
                }

                if (rank.Permissions != null && rank.Permissions.Contains(permission))
                {
                    return true;
                }

                Rank? requiredRank = rankService.RetrieveRanksInCollection().Result.FirstOrDefault(r => r.Permissions != null && r.Permissions.Contains(permission));
                if (requiredRank != null && account.Rank >= requiredRank.RankID)
                {
                    return true;
                }

                return false;
            }
        }

        public class SuspensionService
        {
            private readonly IMongoCollection<Account> _userCollection;
            private readonly IMongoCollection<Suspension> _suspensionCollection;

            public SuspensionService(MongoDBConnection dbConnection)
            {
                _userCollection = dbConnection.Accounts;
                _suspensionCollection = dbConnection.Suspensions;
            }

            public async Task<(bool success, string message)> SuspendAccount(CommandArgs args, string username, string reason, string duration, AccountManagement accountManagement, UserService userService)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found.");
                }

                Suspension existingSuspension = await RetrieveSuspensionByAccountUsername(username);
                if (existingSuspension != null)
                {
                    return (false, "This account is already suspended.");
                }

                TimeSpan totalDuration = accountManagement.ParseTotalSeconds(duration);
                if (totalDuration.TotalSeconds <= 0)
                {
                    return (false, "Invalid duration specified. Please enter a positive number of seconds.");
                }

                DateTime expirationDate = DateTime.UtcNow.Add(totalDuration);
                var issuerUsername = args.Player.GetData<string>("Username");
                Account issuerAccount = await userService.RetrieveAccountByUsername(issuerUsername);

                var newSuspension = new Suspension
                {
                    IssuerID = issuerAccount.AccountID,
                    AccountID = account.AccountID,
                    Reason = reason,
                    IssuedAt = DateTime.UtcNow,
                    ExpirationDate = expirationDate,
                    AssociatedUUIDs = new List<string>(),
                };

                newSuspension.AssociatedUUIDs.Add(account.PlayerUUID);
                await _suspensionCollection.InsertOneAsync(newSuspension);
                return (true, "Account suspended successfully.");
            }

            public async Task<(bool success, string message)> UnsuspendAccount(string username, UserService userService)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found");
                }

                Suspension suspension = await RetrieveSuspensionByAccountUsername(account.Username);
                if (suspension == null)
                {
                    return (false, "The account is not suspended.");
                }

                await _suspensionCollection.DeleteOneAsync(s => s.AccountID == account.AccountID);
                return (true, "The account has been unsuspended");
            }

            public async Task<bool> AddAssociatedUUID(string username, string uuid)
            {
                Account account = await _userCollection.Find(a => a.Username == username).FirstOrDefaultAsync();
                if (account == null)
                {
                    return false;
                }

                Suspension suspension = await RetrieveSuspensionByAccountID(account.AccountID);
                if (suspension == null)
                {
                    return false;
                }

                if (suspension.AssociatedUUIDs.Contains(uuid))
                {
                    return false;
                }

                suspension.AssociatedUUIDs.Add(uuid);
                await _suspensionCollection.ReplaceOneAsync(s => s.AccountID == account.AccountID, suspension);

                return true;
            }

            public async Task<Suspension> RetrieveSuspensionByAccountUsername(string username)
            {
                Account account = await _userCollection.Find(a => a.Username == username).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }

                return await _suspensionCollection.Find(s => s.AccountID == account.AccountID).FirstOrDefaultAsync();
            }

            public async Task<Suspension> RetrieveSuspensionByAccountID(int id)
            {
                return await _suspensionCollection.Find(s => s.AccountID == id).FirstOrDefaultAsync();
            }

            public async Task<Suspension> RetrieveSuspensionByAccountUUID(string uuid)
            {
                return await _suspensionCollection.Find(s => s.AssociatedUUIDs.Contains(uuid)).FirstOrDefaultAsync();
            }
        }

        public class IdentificationService
        {
            public string HashPassword(string password)
            {
                using (var sha256 = SHA256.Create())
                {
                    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
                    return Convert.ToBase64String(bytes);
                }
            }

            public bool VerifyPassword(string password, string storedHash)
            {
                var hash = HashPassword(password);
                return hash == storedHash;
            }
        }

        public class WarningService
        {
            private readonly IMongoCollection<Account> _userCollection;
            private readonly IMongoCollection<Warning> _warningCollection;

            public WarningService(MongoDBConnection dbConnection)
            {
                _userCollection = dbConnection.Accounts;
                _warningCollection = dbConnection.Warnings;
            }

            public async Task<(bool success, string message)> IssueWarning(CommandArgs args, string username, string reason, UserService userService, SuspensionService suspensionService)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found.");
                }

                Suspension existingSuspension = await suspensionService.RetrieveSuspensionByAccountUsername(username);
                if (existingSuspension != null)
                {
                    return (false, "Cannot issue a warning to a suspended account.");
                }

                var issuerUsername = args.Player.GetData<string>("Username");
                Account issuerAccount = await userService.RetrieveAccountByUsername(issuerUsername);

                var newWarning = new Warning
                {
                    IssuerID = issuerAccount.AccountID,
                    AccountID = account.AccountID,
                    WarningID = Guid.NewGuid().ToString(),
                    Reason = reason,
                    IssuedAt = DateTime.UtcNow
                };

                await _warningCollection.InsertOneAsync(newWarning);
                return (true, "Warning issued successfully.");
            }

            public async Task<(bool success, string message)> RemoveWarning(CommandArgs args, string username, string uuid, UserService userService)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found.");
                }

                var result = await _warningCollection.DeleteOneAsync(w => w.WarningID == uuid);
                if (result.DeletedCount == 0)
                {
                    return (false, "Warning not found.");
                }

                return (true, "Warning removed successfully.");
            }

            public async Task<List<Warning>> RetrieveWarningsByAccountUsername(string username)
            {
                Account account = await _userCollection.Find(a => a.Username == username).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }

                return await _warningCollection.Find(w => w.AccountID == account.AccountID).ToListAsync();
            }

            public async Task<List<Warning>> RetrieveWarningsByAccountID(int id)
            {
                return await _warningCollection.Find(w => w.AccountID == id).ToListAsync();
            }
        }

        public class ModLogService
        {
            private readonly IMongoCollection<Account> _userCollection;
            private readonly IMongoCollection<ModCase> _modLogCollection;

            public ModLogService(MongoDBConnection dbConnection)
            {
                _userCollection = dbConnection.Accounts;
                _modLogCollection = dbConnection.ModLogs;
            }

            public async Task<(bool success, string message)> IssueModLog(CommandArgs args, string username, string reason, string action, UserService userService)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found.");
                }

                var lastCase = await _modLogCollection.Find(Builders<ModCase>.Filter.Empty)
                    .Sort(Builders<ModCase>.Sort.Descending("CaseID"))
                    .Limit(1)
                    .FirstOrDefaultAsync();

                int newId = (lastCase?.CaseID ?? 0) + 1;

                var issuerUsername = args.Player.GetData<string>("Username");
                Account issuerAccount = await userService.RetrieveAccountByUsername(issuerUsername);

                var newModCase = new ModCase
                {
                    IssuerID = issuerAccount.AccountID,
                    AccountID = account.AccountID,
                    CaseID = newId,
                    Reason = reason,
                    Action = action,
                    IssuedAt = DateTime.UtcNow
                };

                await _modLogCollection.InsertOneAsync(newModCase);
                return (true, "Mod log issued successfully.");
            }

            public async Task<List<ModCase>> RetrieveModLogsByUsername(string username)
            {
                Account account = await _userCollection.Find(a => a.Username == username).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }

                return await _modLogCollection.Find(m => m.AccountID == account.AccountID).ToListAsync();
            }

            public async Task<List<ModCase>> RetrieveModLogsByID(int id)
            {
                return await _modLogCollection.Find(m => m.AccountID == id).ToListAsync();
            }
        }

        public class MuteService
        {
            private readonly IMongoCollection<Account> _userCollection;
            private readonly IMongoCollection<MuteCase> _muteCollection;

            public MuteService(MongoDBConnection dbConnection)
            {
                _userCollection = dbConnection.Accounts;
                _muteCollection = dbConnection.Mutes;
            }

            public async Task<(bool success, string message)> IssueMute(CommandArgs args, string username, string reason, string duration, UserService userService, AccountManagement accountManagement)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found.");
                }

                MuteCase mute = await RetrieveMuteByUsername(username);
                if (mute != null)
                {
                    return (false, "Account is already muted.");
                }

                TimeSpan totalDuration = accountManagement.ParseTotalSeconds(duration);
                if (totalDuration.TotalSeconds <= 0)
                {
                    return (false, "Invalid duration specified. Please enter a positive number of seconds.");
                }

                DateTime expirationDate = DateTime.UtcNow.Add(totalDuration);

                var issuerUsername = args.Player.GetData<string>("Username");
                Account issuerAccount = await userService.RetrieveAccountByUsername(issuerUsername);

                var newMute = new MuteCase
                {
                    IssuerID = issuerAccount.AccountID,
                    AccountID = account.AccountID,
                    Reason = reason,
                    IssuedAt = DateTime.UtcNow,
                    ExpirationDate = expirationDate
                };

                await _muteCollection.InsertOneAsync(newMute);
                return (true, "Mute issued successfully.");
            }

            public async Task<(bool success, string message)> RevokeMute(CommandArgs args, string username, UserService userService)
            {
                Account account = await userService.RetrieveAccountByUsername(username);
                if (account == null)
                {
                    return (false, "Account not found.");
                }

                MuteCase mute = await RetrieveMuteByUsername(username);
                if (mute == null)
                {
                    return (false, "Account is not muted.");
                }

                var result = await _muteCollection.DeleteOneAsync(m => m.AccountID == account.AccountID);
                if (result.DeletedCount == 0)
                {
                    return (false, "Mute not found.");
                }

                return (true, "Mute revoked successfully.");
            }

            public async Task<MuteCase> RetrieveMuteByUsername(string username)
            {
                Account account = await _userCollection.Find(a => a.Username == username).FirstOrDefaultAsync();
                if (account == null)
                {
                    return null;
                }

                return await _muteCollection.Find(m => m.AccountID == account.AccountID).FirstOrDefaultAsync();
            }

            public async Task<MuteCase> RetrieveMuteByID(int id)
            {
                return await _muteCollection.Find(m => m.AccountID == id).FirstOrDefaultAsync();
            }
        }

        public class HTTPService : IDisposable
        {
            private readonly HttpClient _httpClient;

            public HTTPService()
            {
                _httpClient = new HttpClient();
            }

            public async Task<(bool success, string responseMessage)> SendReportAsync(string webhookUrl, string username, string reason, string proof, string submitter)
            {
                var embed = new
                {
                    title = "New Report on " + username,
                    fields = new[]
                    {
                new { name = "Reason", value = reason, inline = true },
                new { name = "Proof", value = proof, inline = true }
            },
                    footer = new { text = $"Submitted by: {submitter}" }
                };

                var payload = new
                {
                    embeds = new[] { embed }
                };

                return await PostJsonAsync(webhookUrl, payload);
            }

            private async Task<(bool success, string responseMessage)> PostJsonAsync(string url, object data)
            {
                try
                {
                    var json = JsonConvert.SerializeObject(data);
                    var content = new StringContent(json, Encoding.UTF8, "application/json");

                    var response = await _httpClient.PostAsync(url, content);
                    response.EnsureSuccessStatusCode();

                    return (true, await response.Content.ReadAsStringAsync());
                }
                catch (Exception ex)
                {

                    return (false, ex.Message);
                }
            }

            public void Dispose()
            {
                _httpClient.Dispose();
            }
        }

        private TimeSpan ParseTotalSeconds(string input)
        {
            if (int.TryParse(input, out int totalSeconds))
            {
                return TimeSpan.FromSeconds(totalSeconds);
            }
            return TimeSpan.Zero;
        }

        // Database Configuration

        public class MongoDBConnection
        {
            private readonly IMongoDatabase _database;
            private readonly string _userCollection;
            private readonly string _rankCollection;
            private readonly string _suspensionCollection;
            private readonly string _warningCollection;
            private readonly string _modLogCollection;
            private readonly string _muteCollection;

            public MongoDBConnection(string connectionString, string databaseName, AccountManagement accountManagement)
            {
                var client = new MongoClient(connectionString);
                _database = client.GetDatabase(databaseName);

                var config = accountManagement.LoadConfiguration();
                _userCollection = config.Database.AccountCollection;
                _rankCollection = config.Database.RankCollection;
                _suspensionCollection = config.Database.SuspensionCollection;
                _warningCollection = config.Database.WarningCollection;
                _modLogCollection = config.Database.ModLogCollection;
                _muteCollection = config.Database.MuteCollection;
            }

            public IMongoCollection<Account> Accounts => _database.GetCollection<Account>(_userCollection);
            public IMongoCollection<Rank> Ranks => _database.GetCollection<Rank>(_rankCollection);
            public IMongoCollection<Suspension> Suspensions => _database.GetCollection<Suspension>(_suspensionCollection);
            public IMongoCollection<Warning> Warnings => _database.GetCollection<Warning>(_warningCollection);
            public IMongoCollection<ModCase> ModLogs => _database.GetCollection<ModCase>(_modLogCollection);
            public IMongoCollection<MuteCase> Mutes => _database.GetCollection<MuteCase>(_muteCollection);
        }

        private Config LoadConfiguration()
        {
            string filePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("Configuration file not found.", filePath);
            }

            string jsonConfig = File.ReadAllText(filePath);
            var config = JsonConvert.DeserializeObject<Config>(jsonConfig);
            if (config == null)
            {
                throw new InvalidOperationException("Configuration file is invalid or empty.");
            }

            return config;
        }

        public class Config
        {
            public DatabaseSettings Database { get; set; }
            public HTTPSettings HTTP { get; set; }
        }

        public class DatabaseSettings
        {
            public string ConnectionString { get; set; }
            public string DatabaseName { get; set; }
            public string AccountCollection { get; set; }
            public string RankCollection { get; set; }
            public string SuspensionCollection { get; set; }
            public string WarningCollection { get; set; }
            public string ModLogCollection { get; set; }
            public string MuteCollection { get; set; }
        }

        public class HTTPSettings
        {
            public string ReportsChannelWebhook { get; set; }
            public string PriorityReportsChannelWebhook { get; set; }
        }

        public class Account
        {
            [BsonId]
            public ObjectId Id { get; set; }
            public int AccountID { get; set; }
            public string PlayerUUID { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }
            public DateTime RegistrationDate { get; set; }
            public int Rank { get; set; }
            public int Balance { get; set; }
        }

        public class Rank
        {
            [BsonId]
            public int RankID { get; set; }
            public string Name { get; set; }
            public string[]? Permissions { get; set; }
        }

        public class Suspension
        {
            [BsonId]
            public ObjectId Id { get; set; }
            public int IssuerID { get; set; }
            public int AccountID { get; set; }
            public string? Reason { get; set; }
            public DateTime IssuedAt { get; set; }
            public DateTime ExpirationDate { get; set; }
            public List<string>? AssociatedUUIDs { get; set; }
        }

        public class Warning
        {
            [BsonId]
            public ObjectId Id { get; set; }
            public int IssuerID { get; set; }
            public int AccountID { get; set; }
            public string WarningID { get; set; }
            public string? Reason { get; set; }
            public DateTime IssuedAt { get; set; }
        }

        public class ModCase
        {
            [BsonId]
            public ObjectId Id { get; set; }
            public int IssuerID { get; set; }
            public int AccountID { get; set; }
            public int CaseID { get; set; }
            public string? Reason { get; set; }
            public string Action { get; set; }
            public DateTime IssuedAt { get; set; }
        }

        public class MuteCase
        {
            [BsonId]
            public ObjectId Id { get; set; }
            public int IssuerID { get; set; }
            public int AccountID { get; set; }
            public string? Reason { get; set; }
            public DateTime IssuedAt { get; set; }
            public DateTime ExpirationDate { get; set; }
        }
    }
}