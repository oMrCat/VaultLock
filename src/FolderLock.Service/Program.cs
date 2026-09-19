using FolderLock.Service;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "FolderLockGuard");
builder.Services.AddHostedService<WatchdogWorker>();

var host = builder.Build();
host.Run();
