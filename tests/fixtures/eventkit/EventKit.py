"""Test-only EventKit substitute. Never installed with agent_gateway."""

import os

from test_connector_reminders import Due, ListOf, Reminder, When

EKEntityTypeReminder = 1
EKAuthorizationStatusFullAccess = 3
EKReminder = Reminder

PERSON = os.environ["AGW_TEST_REMINDERS_ACCOUNT"]
LIST = ListOf(f"{PERSON}-list", f"{PERSON} private list")
ITEMS = [
    Reminder(f"{PERSON}-open", f"{PERSON} private task", LIST, due=Due(2026, 11, 20), notes=f"{PERSON} private notes"),
    Reminder(f"{PERSON}-done", f"{PERSON} finished task", LIST, done_at=When(1_794_000_000)),
]


class EKEventStore:
    @staticmethod
    def authorizationStatusForEntityType_(kind):
        assert kind == EKEntityTypeReminder
        return EKAuthorizationStatusFullAccess

    @classmethod
    def alloc(cls):
        return cls()

    def init(self):
        return self

    def calendarsForEntityType_(self, kind):
        assert kind == EKEntityTypeReminder
        return [LIST]

    def predicateForCompletedRemindersWithCompletionDateStarting_ending_calendars_(self, start, end, lists):
        return True, lists

    def predicateForIncompleteRemindersWithDueDateStarting_ending_calendars_(self, start, end, lists):
        return False, lists

    def fetchRemindersMatchingPredicate_completion_(self, predicate, callback):
        completed, lists = predicate
        callback([item for item in ITEMS if item.isCompleted() == completed and item.calendar() in lists])

    def calendarItemWithIdentifier_(self, identifier):
        return next((item for item in ITEMS if item.calendarItemIdentifier() == identifier), None)
