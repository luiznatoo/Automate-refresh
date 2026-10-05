import sys,unittest
from pathlib import Path
from unittest.mock import patch,MagicMock
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'outputs'/'central-refresh'))
import central as c

class Tests(unittest.TestCase):
    def test_clean_home_and_secondary_options(self):
        root=c.tk.Tk();root.withdraw();app=c.App(root)
        try:
            self.assertEqual(app.options.state(),'withdrawn')
            self.assertEqual(len(app.buttons),4)
            self.assertTrue(all(b.cget('text')=='Abrir' for b in app.buttons.values()))
            self.assertTrue(all(not v.get() for v in app.messages.values()))
            app.unit.set('UNIDADE TESTE');app.group.set('GRUPO TESTE')
            self.assertIn('UNIDADE TESTE',app.context.get());self.assertIn('GRUPO TESTE',app.context.get())
            app.unit.set('Cadastro local');self.assertEqual(app.context.get(),'Cadastro em cada ferramenta')
            app.open_history_page();root.update_idletasks()
            self.assertEqual(app.options_tabs.select(),app.history_tab)
            self.assertEqual(app.options.state(),'normal')
        finally:app.close()

    def test_catalog_launch_paths(self):
        self.assertEqual(len(c.TOOLS),4)
        for tool in c.TOOLS:
            command,folder=c.launch_command(tool)
            self.assertTrue(Path(command[1]).is_file()); self.assertTrue((folder/'LEIA-ME.md').is_file())
            self.assertNotIn(' ',Path(command[0]).name)
        with self.assertRaises(ValueError): c.tool_folder('../outside')

    def test_window_launch_and_poll(self):
        root=c.tk.Tk(); root.withdraw(); app=c.App(root)
        try:
            process=MagicMock(); process.poll.return_value=None
            with patch.object(c.subprocess,'Popen',return_value=process) as launch:
                app.launch(c.TOOLS[0]); self.assertEqual(launch.call_count,1)
                self.assertFalse(launch.call_args.kwargs['shell'])
                with patch.object(c.messagebox,'showinfo'): app.launch(c.TOOLS[0])
                self.assertEqual(launch.call_count,1)
                root.after_cancel(app.poll_id)
                process.poll.return_value=0; app.poll()
                self.assertNotIn(c.TOOLS[0][0],app.running)
            root.update_idletasks()
        finally: app.close()

if __name__=='__main__': unittest.main()
