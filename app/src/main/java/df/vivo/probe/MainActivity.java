package df.vivo.probe;

import android.app.Activity;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {

    private TextView log;
    private Button run;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);

        run = new Button(this);
        run.setText("Run DFProbe");
        root.addView(run, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        run.setOnClickListener(v -> startProbe());

        ScrollView sc = new ScrollView(this);
        log = new TextView(this);
        log.setTypeface(Typeface.MONOSPACE);
        log.setTextSize(11f);
        log.setText(getIntent() != null ? getIntent().getStringExtra("seed") : "");
        log.setTextIsSelectable(true);
        sc.addView(log);
        root.addView(sc, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        setContentView(root);

        append("DFProbe 0.1 — appender of CVE-2026-43284 (DirtyFrag ESP page-cache write)\n");
        append("Runs the write primitive against THIS APP'S OWN private file only.\n");
        append("Nothing system-wide is patched. Press Run.\n\n");
    }

    private void append(final String s) {
        runOnUiThread(() -> {
            log.append(s);
            android.util.Log.i("DFProbe", s.trim());   // adb logcat -s DFProbe:V
        });
    }

    private void startProbe() {
        run.setEnabled(false);
        append("\n=== RUN " + new java.util.Date() + " ===\n");
        new Thread(() -> {
            try {
                ProbeRunner.run(this, this::append);
            } catch (Throwable t) {
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                append("FATAL: " + sw + "\n");
            } finally {
                runOnUiThread(() -> run.setEnabled(true));
            }
        }).start();
    }
}
