/* collapsible_section.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COLLAPSIBLE_SECTION_H
#define COLLAPSIBLE_SECTION_H

#include <QFrame>
#include <QToolButton>
#include <QVBoxLayout>
#include <QWidget>

/**
 * @brief A collapsible section widget for use in a QSplitter.
 *
 * This widget displays a clickable header that toggles the visibility
 * of the content area. When collapsed, the widget shrinks to just the
 * header height. When expanded, it can be resized via the parent splitter.
 * Multiple CollapsibleSection widgets can be independently expanded or
 * collapsed.
 */
class CollapsibleSection : public QWidget
{
    Q_OBJECT

  public:
    /**
     * @brief Construct a collapsible section.
     * @param title The title displayed in the header.
     * @param parent Optional parent widget.
     */
    explicit CollapsibleSection(const QString &title = QString(),
                                QWidget *parent = nullptr);

    /**
     * @brief Set the content widget for this section.
     * @param contentWidget The widget to display when expanded.
     *
     * The section takes ownership of the widget.
     */
    void setContentWidget(QWidget *contentWidget);

    /**
     * @brief Set the expanded state of the section.
     * @param expanded True to expand, false to collapse.
     */
    void setExpanded(bool expanded);

    /**
     * @brief Check if the section is currently expanded.
     * @return True if expanded, false if collapsed.
     */
    bool isExpanded() const;

    /**
     * @brief Set the title text.
     * @param title The new title.
     */
    void setTitle(const QString &title);

    /**
     * @brief Get the header height (for splitter sizing when collapsed).
     * @return The height of the header in pixels.
     */
    int headerHeight() const;

  signals:
    /**
     * @brief Emitted when the section is toggled.
     * @param expanded True if now expanded, false if collapsed.
     */
    void toggled(bool expanded);

  private slots:
    void onToggle(bool checked);

  private:
    QToolButton *toggleButton;
    QFrame *headerLine;
    QWidget *contentArea;
    QVBoxLayout *mainLayout;
    int savedHeight;
};

#endif // COLLAPSIBLE_SECTION_H
