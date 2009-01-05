using System.Security.Permissions;

[assembly: SecurityPermission(
SecurityAction.RequestMinimum, Execution = true)]
namespace Client
{

    class Program
    {
        static void Main(string[] args)
        {
           new TestEchoWebserviceprovider().RequestEcho();

        }


    }
}
