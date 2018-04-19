#include <conio.h>
#include <process.h>
#include <sched.h>
#include <sema.h>
#include <string.h>

#if !defined (NULL)
#define NULL 0
#endif

int main(int argc , char ** argv)
{
  int policy = -1;
  int quantum;
	int start,elapsed;
  int id1, id2;    	/* ID of child process */

  if (argc == 3) {
    if (!strcmp(argv[1], "rr")) {
      policy = 0;
    } else if (!strcmp(argv[1], "mlf")) {
      policy = 1;
    } else {
      Print("usage: %s [rr|mlf] <quantum>\n", argv[0]);
      Exit(1);
    }
    quantum = atoi(argv[2]);
    Set_Scheduling_Policy(policy, quantum);
  } else {
    Print("usage: %s [rr|mlf] <quantum>\n", argv[0]);
    Exit(1);
  }

  quantum = atoi(argv[2]);
  Set_Scheduling_Policy(policy, quantum);
 start = Get_Time_Of_Day();
  
  id1 = Spawn_Program ( "/c/sched2.exe", "/c/sched2.exe") ;

  id2 = Spawn_Program ( "/c/sched1.exe", "/c/sched1.exe") ;

  Wait(id1);
  Wait(id2);
  //Wait(id3);
elapsed = Get_Time_Of_Day() - start;
  Print("\n");
 Print ("Tests Completed at %d\n", elapsed) ;
  return 0;
}
