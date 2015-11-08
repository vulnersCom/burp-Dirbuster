package burp.zn.gui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class DirBusterTable extends JTable {

    private static final long serialVersionUID = 1L;

    public DirBusterTable() {
        super();
        DefaultTableModel model = new DefaultTableModel();
        model.addColumn("");
        model.addColumn("Host");
        model.addColumn("Status code");

        setModel(model);
        getColumnModel().getColumn(0).setMaxWidth(50);
    }

    @Override
    public Class getColumnClass(int column) {
        switch (column) {
            case 0:
                return Boolean.class;
            default:
                return String.class;
        }
    }
}
