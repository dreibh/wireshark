/* collapsible_section.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "collapsible_section.h"

#include <QFont>
#include <QGuiApplication>
#include <QSplitter>

CollapsibleSection::CollapsibleSection(const QString &title, QWidget *parent)
    : QWidget(parent), savedHeight(100)
{
    QFont headerFont(QGuiApplication::font());
    headerFont.setBold(true);

    // Toggle button with arrow indicator
    toggleButton = new QToolButton(this);
    toggleButton->setFont(headerFont);
    toggleButton->setStyleSheet(
        QStringLiteral("QToolButton { border: none; font-weight: bold; }"));
    toggleButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toggleButton->setArrowType(Qt::ArrowType::RightArrow);
    toggleButton->setText(title);
    toggleButton->setCheckable(true);
    toggleButton->setChecked(false);
    toggleButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Horizontal line after header
    headerLine = new QFrame(this);
    headerLine->setFrameShape(QFrame::HLine);
    headerLine->setFrameShadow(QFrame::Sunken);
    headerLine->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    // Header layout (button + line)
    QHBoxLayout *headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(4);
    headerLayout->addWidget(toggleButton);
    headerLayout->addWidget(headerLine, 1);

    // Content area - initially hidden
    contentArea = new QWidget(this);
    contentArea->setVisible(false);
    contentArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    // Main layout
    mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(2);
    mainLayout->addLayout(headerLayout);
    mainLayout->addWidget(contentArea, 1);

    // Set size policy to work well in splitter
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    connect(toggleButton, &QToolButton::clicked, this,
            &CollapsibleSection::onToggle);
}

void CollapsibleSection::setContentWidget(QWidget *contentWidget)
{
    // Remove old layout if exists
    if (contentArea->layout())
    {
        QLayoutItem *item;
        while ((item = contentArea->layout()->takeAt(0)) != nullptr)
        {
            delete item->widget();
            delete item;
        }
        delete contentArea->layout();
    }

    // Create new layout with the content widget
    QVBoxLayout *layout = new QVBoxLayout(contentArea);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(contentWidget);
}

void CollapsibleSection::setExpanded(bool expanded)
{
    toggleButton->setChecked(expanded);
    onToggle(expanded);
}

bool CollapsibleSection::isExpanded() const
{
    return toggleButton->isChecked();
}

void CollapsibleSection::setTitle(const QString &title)
{
    toggleButton->setText(title);
}

int CollapsibleSection::headerHeight() const
{
    return toggleButton->sizeHint().height() + 4;
}

void CollapsibleSection::onToggle(bool checked)
{
    toggleButton->setArrowType(checked ? Qt::ArrowType::DownArrow
                                       : Qt::ArrowType::RightArrow);

    // Find parent splitter to adjust sizes
    QSplitter *splitter = qobject_cast<QSplitter *>(parentWidget());

    if (checked)
    {
        // Expanding
        contentArea->setVisible(true);
        setMinimumHeight(0);
        setMaximumHeight(QWIDGETSIZE_MAX);

        if (splitter)
        {
            int idx = splitter->indexOf(this);
            if (idx >= 0)
            {
                QList<int> sizes = splitter->sizes();
                // Restore saved height or use reasonable default
                sizes[idx] = qMax(savedHeight, headerHeight() + 50);
                splitter->setSizes(sizes);
            }
        }
    }
    else
    {
        // Collapsing - save current height first
        if (splitter)
        {
            int idx = splitter->indexOf(this);
            if (idx >= 0)
            {
                QList<int> sizes = splitter->sizes();
                if (sizes[idx] > headerHeight())
                {
                    savedHeight = sizes[idx];
                }
            }
        }

        contentArea->setVisible(false);
        int hh = headerHeight();
        setMinimumHeight(hh);
        setMaximumHeight(hh);
    }

    emit toggled(checked);
}
