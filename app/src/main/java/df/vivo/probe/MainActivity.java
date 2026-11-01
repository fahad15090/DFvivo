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
    private Button hook;
    private Button unpatch;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(24, 24, 24, 24);

        run = new Button(this);
        run.setText("Run DFProbe (stage 1)");
        root.addView(run, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        run.setOnClickListener(v -> startProbe());

        hook = new Button(this);
        hook.setText("Hook libc++ + Fire (stage 2 full)");
        root.addView(hook, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        hook.setOnClickListener(v -> startHook("full"));

        unpatch = new Button(this);
        unpatch.setText("Unpatch libc++ (restore)");
        root.addView(unpatch, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        unpatch.setOnClickListener(v -> startHook("unpatch"));

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

        append("DFvivo 0.2 — CVE-2026-43284 (DirtyFrag) root probe\n");
        append("Stage 1: write primitive vs app's own file.\n");
        append("Stage 2 full: hook libc++ ostream::sentry, orphan-trigger init,\n");
        append("marker check at /dev/dfd, stays patched until \"Unpatch libc++\".\n\n");
    }

    private void append(final String s) {
        runOnUiThread(() -> {
            log.append(s);
            android.util.Log.i("DFProbe", s.trim());   // adb logcat -s DFProbe:V
        });
    }

    private void startProbe() {
        run.setEnabled(false);
        hook.setEnabled(false);
        unpatch.setEnabled(false);
        append("\n=== RUN " + new java.util.Date() + " ===\n");
        new Thread(() -> {
            try {
                ProbeRunner.run(this, this::append);
            } catch (Throwable t) {
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                append("FATAL: " + sw + "\n");
            } finally {
                runOnUiThread(() -> { run.setEnabled(true); hook.setEnabled(true); unpatch.setEnabled(true); });
            }
        }).start();
    }

    private void startHook(final String mode) {
        run.setEnabled(false);
        hook.setEnabled(false);
        unpatch.setEnabled(false);
        append("\n=== HOOK(" + mode + ") " + new java.util.Date() + " ===\n");
        new Thread(() -> {
            try {
                ProbeRunner.runHook(this, this::append, mode);
            } catch (Throwable t) {
                java.io.StringWriter sw = new java.io.StringWriter();
                t.printStackTrace(new java.io.PrintWriter(sw));
                append("FATAL: " + sw + "\n");
            } finally {
                runOnUiThread(() -> { run.setEnabled(true); hook.setEnabled(true); unpatch.setEnabled(true); });
            }
        }).start();
    }
}
