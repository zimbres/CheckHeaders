var builder = DistributedApplication.CreateBuilder(args);

builder.AddProject<Projects.CheckHeaders>("checkheaders");

builder.Build().Run();
