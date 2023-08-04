/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MANUF_DIALOG_H
#define MANUF_DIALOG_H

#include <wireshark_dialog.h>
#include <models/manuf_table_model.h>

namespace Ui {
class ManufDialog;
}

class ManufDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit ManufDialog(QWidget &parent, CaptureFile &cf);
    ~ManufDialog();

private slots:
    void on_editingFinished(void);
    void copyToClipboard(void);

private:
    void searchPrefix(QString &text);
    void searchVendor(QString &text);

    Ui::ManufDialog *ui;
    ManufTableModel *model_;
};

#endif // MANUF_DIALOG_H
